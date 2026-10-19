//! Independently pinned immutable application metadata, not proof receipts.
use crate::{Error, Result, contract_digest};
use bfv_key_transform::{Expected as KeyExpected, SetupDescriptor, Statement as KeyStatement};
use bfv_query_core::{BfvKeyAnchor, PublicSetup};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use registry200_journal::{Application as SourceSpec, ApplicationDescriptor};
use registry200_proof::{Val, source::statement::decode_digest};
use sha2::{Digest, Sha256, Sha512};
use version_journal::{Genesis, Hash};

pub const DESCRIPTOR_BYTES: usize = 896;
const MAGIC: &[u8; 8] = b"DCSJAD01";

#[derive(Clone)]
pub struct Descriptor {
    spec: ApplicationDescriptor,
    object: [u8; 32],
    setup_id: [u8; 32],
    setup_digest: [u8; 64],
    anchor: [u8; BfvKeyAnchor::CLAIM_BYTES],
    key: KeyStatement,
}
impl Descriptor {
    /// All pins must originate in the owner's independently authenticated application.
    /// Key33 and anchor metadata do not themselves verify any cryptographic proof.
    pub fn checked(
        spec: ApplicationDescriptor,
        object: [u8; 32],
        setup: &PublicSetup,
        anchor: &BfvKeyAnchor,
        key: &KeyStatement,
    ) -> Result<Self> {
        let bytes = setup.to_bytes().map_err(|_| Error::Domain)?;
        if bytes.is_empty() || bytes.len() > crate::MAX_SETUP_BYTES {
            return Err(Error::ResourceLimit);
        }
        let x = Self {
            spec,
            object,
            setup_id: Sha256::digest(&bytes).into(),
            setup_digest: Sha512::digest(&bytes).into(),
            anchor: anchor
                .encode_claim()
                .map_err(|_| Error::Domain)?
                .try_into()
                .map_err(|_| Error::Encoding)?,
            key: key.clone(),
        };
        x.require_structure()?;
        x.require_setup(setup)?;
        Ok(x)
    }
    pub fn source_spec(&self) -> Result<SourceSpec> {
        Ok(self.spec.application()?)
    }
    pub fn source_object(&self) -> [u8; 32] {
        self.object
    }
    pub fn full_setup_id(&self) -> [u8; 32] {
        self.setup_id
    }
    pub fn full_setup_digest(&self) -> [u8; 64] {
        self.setup_digest
    }
    pub fn id(&self) -> Hash {
        let mut h = Sha256::new();
        h.update(b"DCS/REGISTRY200-JOINT/application/v1");
        h.update(self.encode());
        h.finalize().into()
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(DESCRIPTOR_BYTES);
        b.extend_from_slice(MAGIC);
        b.extend_from_slice(&contract_digest());
        b.extend(self.spec.encode());
        b.extend_from_slice(&self.object);
        b.extend_from_slice(&self.setup_id);
        b.extend_from_slice(&self.setup_digest);
        b.extend_from_slice(&self.anchor);
        for v in self.key.public_values() {
            b.extend_from_slice(&v.as_canonical_u64().to_le_bytes());
        }
        b.extend_from_slice(&[0; 12]);
        b
    }
    /// Canonical metadata only. The verifier still restores/hash-checks the original
    /// setup from the depot and rechecks its anchor before accepting any candidate.
    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() != DESCRIPTOR_BYTES
            || &b[..8] != MAGIC
            || b[8..40] != contract_digest()
            || b[884..896] != [0; 12]
        {
            return Err(Error::Encoding);
        }
        let x = Self {
            spec: ApplicationDescriptor::decode(&b[40..352])?,
            object: b[352..384].try_into().unwrap(),
            setup_id: b[384..416].try_into().unwrap(),
            setup_digest: b[416..480].try_into().unwrap(),
            anchor: b[480..620].try_into().unwrap(),
            key: decode_key(&b[620..884])?,
        };
        x.require_structure()?;
        if x.encode() != b {
            return Err(Error::Encoding);
        }
        Ok(x)
    }
    fn require_structure(&self) -> Result<()> {
        let app = self.source_spec()?;
        if &self.anchor[..8] != b"BFVKAC01"
            || self.anchor[8..24] != app.database
            || self.anchor[44..76] != self.setup_id
        {
            return Err(Error::Domain);
        }
        let _ = decode_digest(self.anchor[108..140].try_into().unwrap())
            .map_err(|_| Error::Encoding)?;
        let k = &self.key.expected;
        if k.descriptor.database != app.database
            || k.descriptor.key_domain != self.anchor[24..40]
            || k.descriptor.key_epoch != u32::from_le_bytes(self.anchor[40..44].try_into().unwrap())
            || k.descriptor.public_setup_digest != self.anchor[76..108]
            || registry200_proof::source::statement::encode_digest(k.coefficients)
                != self.anchor[108..140]
        {
            return Err(Error::Domain);
        }
        Ok(())
    }
    pub(crate) fn require_setup(&self, setup: &PublicSetup) -> Result<BfvKeyAnchor> {
        let b = setup.to_bytes().map_err(|_| Error::Domain)?;
        self.require_setup_bytes(&b)?;
        let anchor = setup
            .decode_key_anchor_claim(&self.anchor)
            .map_err(|_| Error::Domain)?;
        if anchor.full_setup_id() != self.setup_id {
            return Err(Error::Domain);
        }
        Ok(anchor)
    }
    pub(crate) fn require_setup_bytes(&self, b: &[u8]) -> Result<()> {
        if b.is_empty() || b.len() > crate::MAX_SETUP_BYTES {
            return Err(Error::ResourceLimit);
        }
        if <[u8; 32]>::from(Sha256::digest(b)) != self.setup_id
            || <[u8; 64]>::from(Sha512::digest(b)) != self.setup_digest
        {
            return Err(Error::Domain);
        }
        Ok(())
    }
    pub(crate) fn require_provenance(&self, p: &bfv_mul_relin_proof::Provenance) -> Result<()> {
        if p.anchor()
            .encode_claim()
            .map_err(|_| Error::Domain)?
            .as_slice()
            != self.anchor
            || p.original_setup_digest() != self.setup_digest
        {
            return Err(Error::Domain);
        }
        let full = self.key.public_values();
        for s in p.encodings() {
            if s.expected.bfv().full_setup() != self.setup_id
                || s.expected.bfv().key().public_values() != full
            {
                return Err(Error::Domain);
            }
        }
        Ok(())
    }
}

fn decode_key(b: &[u8]) -> Result<KeyStatement> {
    if b.len() != 264 {
        return Err(Error::Encoding);
    }
    let mut v = [Val::ZERO; 33];
    for (value, bytes) in v.iter_mut().zip(b.as_chunks::<8>().0) {
        let n = u64::from_le_bytes(*bytes);
        if n >= Val::ORDER_U64 {
            return Err(Error::Encoding);
        }
        *value = Val::from_u64(n);
    }
    let mut prefix = Vec::with_capacity(100);
    for value in &v[..25] {
        prefix.extend_from_slice(
            &u32::try_from(value.as_canonical_u64())
                .map_err(|_| Error::Encoding)?
                .to_le_bytes(),
        );
    }
    if prefix[..32] != bfv_key_transform::profile_digest() {
        return Err(Error::Domain);
    }
    Ok(KeyStatement {
        expected: KeyExpected {
            descriptor: SetupDescriptor {
                database: prefix[32..48].try_into().unwrap(),
                key_domain: prefix[48..64].try_into().unwrap(),
                public_setup_digest: prefix[64..96].try_into().unwrap(),
                key_epoch: u32::from_le_bytes(prefix[96..100].try_into().unwrap()),
            },
            coefficients: v[25..29].try_into().unwrap(),
        },
        transformed: v[29..33].try_into().unwrap(),
    })
}

/// New outer application. The old SourceSpec is an inner proof/head namespace;
/// it is never asked to accept this new Genesis application commitment.
pub struct Application {
    descriptor: Descriptor,
    source: SourceSpec,
    genesis: Hash,
}
impl Application {
    pub fn new(descriptor: Descriptor, genesis: &Genesis) -> Result<Self> {
        let descriptor = Descriptor::decode(&descriptor.encode())?;
        let source = descriptor.source_spec()?;
        genesis.validate()?;
        if genesis.network_id != source.network
            || genesis.database != source.database
            || genesis.application_commitment != descriptor.id()
            || genesis.initial_shards != source.initial_shards()
        {
            return Err(Error::Domain);
        }
        Ok(Self {
            descriptor,
            source,
            genesis: genesis.id()?,
        })
    }
    pub fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }
    pub fn source_spec(&self) -> &SourceSpec {
        &self.source
    }
    pub fn id(&self) -> Hash {
        self.descriptor.id()
    }
    pub fn genesis(&self) -> Hash {
        self.genesis
    }
}
