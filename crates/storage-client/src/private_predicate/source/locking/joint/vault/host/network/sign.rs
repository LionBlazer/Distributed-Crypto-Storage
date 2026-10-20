//! Canonical owner permission and actual branch mining, not application admission.
use super::*;
use registry200_journal::Control;
use std::time::{SystemTime, UNIX_EPOCH};
use version_journal::{AuthorizedTransition, Body, ShardUpdate};

impl JointSqlNetworkHost {
    pub(super) fn signed_candidate(
        &self,
        draft: &OwnerVaultDraft,
        operation: &Operation,
    ) -> NetworkResult<Option<CandidateBlock>> {
        let binding = &self.host.vault.pins.binding;
        let spec = binding.application_descriptor().source_spec()?;
        let request = draft.request()?;
        let manifest = draft.manifest()?;
        let parent = draft.parent();
        let next = Control::Active {
            enrollment: request.inner().enrollment,
            registry: manifest.next_root(),
        };
        let mut transition = AuthorizedTransition {
            parent: parent.head().block,
            request: request.encode()?,
            updates: vec![ShardUpdate {
                id: spec.control_id,
                old: parent.control().heads(&spec),
                new: next.heads(&spec),
            }],
            proof: manifest.encode(),
            owner_signature: [0; 64],
        };
        transition.sign(parent.head().genesis, &self.signer);
        let body = Body::Transition(transition);
        // Uses the SAME private Journal, actual next target/state and median
        // timestamp rules. No fixture target, fabricated state or generic Journal.
        // Two legitimate operations may finish in one wall-clock second. Wait
        // for a genuine permitted timestamp instead of inventing a future one.
        let mut header = loop {
            if operation.check().is_err() {
                return Ok(None);
            }
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| io::Error::other("Owner wall clock precedes UNIX epoch"))?
                .as_secs();
            match self
                .host
                .vault
                .history
                .candidate_header(parent, &body, now, now)
            {
                Ok(header) => break header,
                Err(registry200_finality::joint::Error::Journal(
                    version_journal::Error::InvalidTimestamp,
                )) => thread::park_timeout(Duration::from_millis(50)),
                Err(error) => return Err(error.into()),
            }
        };
        let mut remaining = self.config.mining_attempts;
        while remaining != 0 {
            if operation.check().is_err() {
                return Ok(None);
            }
            let chunk = remaining.min(4096);
            match header.mine(chunk) {
                Ok(_) => {
                    return Ok(Some(CandidateBlock::new(
                        header,
                        body.encode(&binding.journal_genesis().profile)?,
                    )?));
                }
                Err(version_journal::Error::MiningExhausted) => remaining -= chunk,
                Err(error) => return Err(error.into()),
            }
        }
        Err(version_journal::Error::MiningExhausted.into())
    }
}
