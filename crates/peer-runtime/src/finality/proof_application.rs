//! Closed installed application pairing. Only bounded public bytes cross this
//! boundary; neither a manifest nor a catalog is a verified operation.
use super::{error, invalid, joint_wire, progress_wire};
use bfv_product_evidence::{CatalogClaim, CatalogId};
use peer_transport::{Connector, Endpoint};
use protocol_storage::BlobId;
use registry200_finality::{CandidateBlock, joint::JointBinding, progress::Binding};
use registry200_joint::{JointEvidenceIngress, progress::ProgressEvidenceIngress};
use std::io;
use version_journal::{Body, Genesis};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Joint,
    Progress,
}
impl Kind {
    pub fn checkpoint_cap(self) -> usize {
        match self {
            Self::Joint => registry200_finality::joint::MAX_CHECKPOINT_BYTES,
            Self::Progress => registry200_finality::progress::MAX_CHECKPOINT_BYTES,
        }
    }
    pub fn encode(self, binding: [u8; 32], tag: u8, bytes: &[u8]) -> io::Result<Vec<u8>> {
        match self {
            Self::Joint => joint_wire::encode(binding, tag, bytes),
            Self::Progress => progress_wire::encode(binding, tag, bytes),
        }
    }
    pub fn decode(self, binding: [u8; 32], bytes: &[u8]) -> io::Result<(u8, &[u8])> {
        match self {
            Self::Joint => joint_wire::decode(binding, bytes),
            Self::Progress => progress_wire::decode(binding, bytes),
        }
    }
}
#[derive(Clone)]
pub(super) enum Installed {
    Joint {
        binding: JointBinding,
        ingress: JointEvidenceIngress,
    },
    Progress {
        binding: Binding,
        ingress: ProgressEvidenceIngress,
    },
}
pub(super) struct Reference {
    pub ordinal: usize,
    pub id: BlobId,
    pub cap: usize,
    pub catalog: bool,
}
impl Installed {
    pub fn kind(&self) -> Kind {
        match self {
            Self::Joint { .. } => Kind::Joint,
            Self::Progress { .. } => Kind::Progress,
        }
    }
    pub fn id(&self) -> [u8; 32] {
        match self {
            Self::Joint { binding, .. } => binding.id(),
            Self::Progress { binding, .. } => binding.id(),
        }
    }
    pub fn genesis(&self) -> &Genesis {
        match self {
            Self::Joint { binding, .. } => binding.journal_genesis(),
            Self::Progress { binding, .. } => binding.journal_genesis(),
        }
    }
    pub fn client(&self, connector: Connector, endpoint: Endpoint) -> super::proof_client::Client {
        super::proof_client::Client::new(connector, endpoint, self.kind(), self.id())
    }
    pub fn read(&self, id: BlobId, cap: usize) -> io::Result<Vec<u8>> {
        match self {
            Self::Joint { ingress, .. } => ingress.read_public_blob(id, cap).map_err(|e| match e {
                registry200_joint::Error::Storage(e) => blob_error(e),
                e => error(e),
            }),
            Self::Progress { ingress, .. } => {
                ingress.read_public_blob(id, cap).map_err(|e| match e {
                    registry200_joint::progress::Error::Storage(e) => blob_error(e),
                    e => error(e),
                })
            }
        }
    }
    pub fn retain(&self, bytes: &[u8]) -> io::Result<BlobId> {
        match self {
            Self::Joint { ingress, .. } => ingress.retain_public_blob(bytes).map_err(error),
            Self::Progress { ingress, .. } => ingress.retain_public_blob(bytes).map_err(error),
        }
    }
    pub fn catalog(&self, id: CatalogId) -> io::Result<CatalogClaim> {
        match self {
            Self::Joint { ingress, .. } => ingress.catalog_claim(id).map_err(error),
            Self::Progress { ingress, .. } => ingress.catalog_claim(id).map_err(error),
        }
    }
    pub fn require_setup(&self, claim: &CatalogClaim) -> io::Result<()> {
        let (bytes, parts) = match self {
            Self::Joint { binding, .. } => {
                (binding.setup_claim().bytes(), binding.setup_claim().parts())
            }
            Self::Progress { binding, .. } => {
                (binding.setup_claim().bytes(), binding.setup_claim().parts())
            }
        };
        if claim.setup_bytes() != bytes || claim.setup_parts() != parts {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn references(
        &self,
        block: &CandidateBlock,
        parent: Option<[u8; 32]>,
    ) -> io::Result<Vec<Reference>> {
        let genesis = self.genesis();
        let g = genesis.id().map_err(error)?;
        let header = block.header();
        if header.genesis != g
            || header.body_hash != version_journal::hash(block.body())
            || parent.is_some_and(|p| header.parent != p)
        {
            return Err(invalid());
        }
        let Body::Transition(body) = Body::decode(block.body(), &genesis.profile).map_err(error)?
        else {
            return Err(invalid());
        };
        if body.parent != header.parent {
            return Err(invalid());
        }
        body.check_authorization(&genesis.owner, g).map_err(error)?;
        match self {
            Self::Joint { binding, .. } => {
                use registry200_joint::{Application, Manifest, ManifestRole, Request};
                let app = Application::new(binding.application_descriptor().clone(), genesis)
                    .map_err(error)?;
                let request = Request::decode(&body.request).map_err(error)?;
                let checked =
                    Request::new(&app, request.lane(), request.inner().clone()).map_err(error)?;
                if checked.encode().map_err(error)? != body.request
                    || checked.inner().parent != header.parent
                {
                    return Err(invalid());
                }
                let manifest = Manifest::decode(&body.proof).map_err(error)?;
                if manifest.lane() != checked.lane() {
                    return Err(invalid());
                }
                Ok(manifest
                    .references()
                    .map(|r| Reference {
                        ordinal: r.ordinal(),
                        id: r.blob_id(),
                        cap: r.byte_cap(),
                        catalog: r.role() == ManifestRole::ProductCatalog,
                    })
                    .collect())
            }
            Self::Progress { binding, .. } => {
                use registry200_joint::progress::{Application, Manifest, ManifestRole, Request};
                let app = Application::new(binding.application_descriptor().clone(), genesis)
                    .map_err(error)?;
                let request = Request::decode(&body.request).map_err(error)?;
                let checked =
                    Request::new(&app, request.lane(), request.inner().clone()).map_err(error)?;
                if checked.encode().map_err(error)? != body.request
                    || checked.inner().parent != header.parent
                {
                    return Err(invalid());
                }
                let manifest = Manifest::decode(&body.proof).map_err(error)?;
                if manifest.lane() != checked.lane() {
                    return Err(invalid());
                }
                Ok(manifest
                    .references()
                    .map(|r| Reference {
                        ordinal: r.ordinal(),
                        id: r.blob_id(),
                        cap: r.byte_cap(),
                        catalog: r.role() == ManifestRole::ProductCatalog,
                    })
                    .collect())
            }
        }
    }
}
fn blob_error(e: bfv_product_evidence::Error) -> io::Error {
    // Only an actually absent immutable file is eligible for network fetching.
    // Corruption, quota poison and all other errors remain hard failures.
    match e {
        bfv_product_evidence::Error::Io(e) if e.kind() == io::ErrorKind::NotFound => e,
        bfv_product_evidence::Error::Storage(protocol_storage::Error::Io(e))
            if e.kind() == io::ErrorKind::NotFound =>
        {
            e
        }
        e => error(e),
    }
}
