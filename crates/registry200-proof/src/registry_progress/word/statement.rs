//! Canonical original private Stmt96 encoding. No query result or proof is computed.
use super::{Error, PrivateInputs, Result};
use crate::Val;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use zeroize::Zeroizing;

/// Independently selected public metadata, without Source/OldRoot authority.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct StatementDomain {
    pub scope: [Val; 16],
    pub enrollment: [Val; 4],
}
/// Owner-private serialized opening; consuming export remains guarded plaintext.
/// ```compile_fail
/// fn copy(x:&registry200_proof::registry_progress::word::StatementOpening) { let _=x.clone().into_words(); }
/// ```
pub struct StatementOpening {
    words: Zeroizing<[u64; 96]>,
    root: [Val; 4],
}
impl StatementOpening {
    pub fn root(&self) -> [Val; 4] {
        self.root
    }
    pub fn into_words(self) -> Zeroizing<[u64; 96]> {
        self.words
    }
}
impl PrivateInputs {
    /// Encode the original mask/policy and actor snapshot from these SAME inputs.
    /// Native Word verification is still necessary to prove their full semantics.
    pub fn statement_opening(&self, domain: &StatementDomain) -> Result<StatementOpening> {
        let p = &self.inner;
        let c = &p.command;
        let w = &p.walk;
        if c.op != 1
            || !(1..=4).contains(&c.mode)
            || c.wait > 2
            || c.offset > 4
            || c.limit > 4
            || !(1..=3).contains(&c.projection)
            || c.abort
            || c.name != [0; 8]
            || w.call == 0
            || w.client == [Val::ZERO; 8]
            || w.invocation == [Val::ZERO; 8]
        {
            return Err(Error::Shape);
        }
        let snapshot = p
            .statement_snapshot(domain.enrollment)
            .ok_or(Error::Binding)?;
        if domain
            .scope
            .iter()
            .chain(&w.client)
            .chain(&w.invocation)
            .chain(&w.sql)
            .chain(&snapshot)
            .chain(&p.controllers[c.principal - 1])
            .any(|v| v.as_canonical_u64() > u64::from(u32::MAX))
        {
            return Err(Error::Shape);
        }
        let mut words = Zeroizing::new([0u64; 96]);
        words[..13].copy_from_slice(&super::statement_header().map(|v| v.as_canonical_u64()));
        words[13..29].copy_from_slice(&domain.scope.map(|v| v.as_canonical_u64()));
        words[29..33].copy_from_slice(&domain.enrollment.map(|v| v.as_canonical_u64()));
        words[33..41].copy_from_slice(&w.client.map(|v| v.as_canonical_u64()));
        words[41..43].copy_from_slice(&[w.call as u32 as u64, (w.call >> 32) as u32 as u64]);
        words[43..45].copy_from_slice(&[c.id as u32 as u64, (c.id >> 32) as u32 as u64]);
        words[45] = c.principal as u64;
        words[46..54]
            .copy_from_slice(&p.controllers[c.principal - 1].map(|v| v.as_canonical_u64()));
        words[54..62].copy_from_slice(&w.invocation.map(|v| v.as_canonical_u64()));
        words[62..70].copy_from_slice(&w.sql.map(|v| v.as_canonical_u64()));
        words[70..78].copy_from_slice(&snapshot.map(|v| v.as_canonical_u64()));
        for (out, bytes) in words[78..86].iter_mut().zip(p.mask.as_chunks::<4>().0) {
            *out = u32::from_le_bytes(*bytes) as u64;
        }
        words[86..91]
            .copy_from_slice(&[c.mode, c.wait, c.offset, c.limit, c.projection].map(u64::from));
        words[91..95].copy_from_slice(&w.statement_salt.map(|v| v.as_canonical_u64()));
        let mut state = Fields([Val::ZERO; 12]);
        let mut scratch = Fields([Val::ZERO; 248]);
        for block in words.as_chunks::<8>().0 {
            state.0[..8].copy_from_slice(&block.map(Val::from_u64));
            state.0 = bfv_hiding_stark::poseidon::write(&mut scratch.0, state.0);
        }
        Ok(StatementOpening {
            words,
            root: core::array::from_fn(|i| state.0[i]),
        })
    }
}
struct Fields<const N: usize>([Val; N]);
impl<const N: usize> Drop for Fields<N> {
    fn drop(&mut self) {
        self.0.fill(Val::ZERO);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry_progress::{
        word,
        word_inventory::owner_cases::{self, Kind},
    };
    #[test]
    fn normal_statement_encoder_preserves_every_original_predicate_case_and_root() {
        for kind in Kind::ALL.into_iter().filter(|k| k.predicate()) {
            let mut case = owner_cases::case(kind);
            let independent = owner_cases::statement(&case.metadata, &case.input, &case.old);
            let p = &mut case.input;
            let inputs = word::PrivateInputs::new(
                word::SourceOpening::checked(
                    Zeroizing::new(
                        p.source
                            .iter()
                            .flat_map(|v| {
                                u32::try_from(v.as_canonical_u64()).unwrap().to_le_bytes()
                            })
                            .collect(),
                    ),
                    Zeroizing::new(p.source_salt.map(|v| v.as_canonical_u64())),
                )
                .unwrap(),
                word::RegistryOpening::new(p.controllers, p.banks),
                core::mem::take(&mut p.command),
                core::mem::take(&mut p.walk),
                Zeroizing::new(p.mask),
                p.salts,
            );
            let domain = StatementDomain {
                scope: case.metadata.scope,
                enrollment: case.metadata.enrollment,
            };
            let opening = inputs.statement_opening(&domain).unwrap();
            assert_eq!(opening.root(), case.metadata.statement, "{}", kind.label());
            assert_eq!(
                opening.into_words().as_slice(),
                independent
                    .iter()
                    .map(|v| v.as_canonical_u64())
                    .collect::<Vec<_>>()
                    .as_slice(),
                "{}",
                kind.label()
            );
            let mut changed = domain;
            changed.enrollment[0] += Val::ONE;
            assert!(matches!(
                inputs.statement_opening(&changed),
                Err(Error::Binding)
            ));
        }
    }
}
