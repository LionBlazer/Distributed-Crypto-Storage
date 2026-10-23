//! Internal complete word relation with constrained PUBLIC309 and native proofs.
//! Independently owned public setup grants no SQL or accepted-state capability.
mod air;
mod canonical;
#[cfg(test)]
mod check;
mod control;
mod evaluate;
mod expr;
#[cfg(test)]
mod generalized_mu;
pub(super) mod owner;
mod plan;
mod predicate;
pub(super) mod preparation;
#[cfg(test)]
mod public_tests;
mod public_values;
mod recipes;
mod schema;
mod streams;
mod structural_setup;
#[cfg(test)]
mod tests;
mod witness;
#[cfg(test)]
mod witness_tests;
use crate::{
    Val,
    source::{self, version::SourceVersionExpected},
};
use expr::Builder;
#[cfg(test)]
use expr::Pool;
use p3_field::PrimeCharacteristicRing;
use schema::*;
#[cfg(test)]
use sha2::Sha512;
use sha2::{Digest, Sha256};
const TARGET_HEIGHT: usize = 512;
pub(super) const PROFILE_DOMAIN:&[u8]=b"DCS/research/word208/StateVersion-Cmd160-Stmt96/H512/v2/structuralPP/direct309PUBLIC/no-value-fold/fullSource680/fullP2/typed-u32/fixedPolicy25/Mask256-four-duplicates/relativeOldRoot-no-proof";
pub(super) fn profile() -> [u8; 32] {
    Sha256::digest(PROFILE_DOMAIN).into()
}
pub(super) fn domain(label: &str) -> [Val; 4] {
    let mut h = Sha256::new();
    h.update(PROFILE_DOMAIN);
    h.update((label.len() as u64).to_le_bytes());
    h.update(label);
    let bytes: [u8; 32] = h.finalize().into();
    source::statement::words(&bytes[..16])
        .collect::<Vec<_>>()
        .try_into()
        .expect("domain4")
}
pub(super) fn header(label: &str) -> Vec<Val> {
    domain(label)
        .into_iter()
        .chain([Val::ONE])
        .chain(source::statement::words(&profile()))
        .collect()
}
/// Metadata is private and unproved. A future receiving boundary must obtain the
/// entire SourceVersion + independently confirmed OldRoot/bootstrap association.
/// This inspector cannot install metadata or turn it into a proof capability.
#[derive(Clone)]
pub(super) struct Metadata {
    pub(super) source: SourceVersionExpected,
    pub(super) predicate: bool,
    pub(super) registry_header: [Val; 33],
    pub(super) enrollment_header: [Val; 33],
    pub(super) context: [Val; 100],
    pub(super) scope: [Val; 16],
    pub(super) parent: [Val; 8],
    pub(super) enrollment: [Val; 4],
    pub(super) old: [Val; 4],
    pub(super) command: [Val; 4],
    pub(super) statement: [Val; 4],
    pub(super) next: [Val; 4],
    pub(super) result: [Val; 4],
    pub(super) blind_sql: [Val; 8],
}
impl Metadata {
    #[cfg(test)]
    fn sample(predicate: bool) -> Self {
        // Only a bounded PUBLIC metadata example, without Source proving, SDK FHE,
        // a private witness or an assertion that these arbitrary roots open.
        let old = super::air_snapshot_tests::statements().0;
        let s = old.expected.source();
        let images: [Vec<u8>; 2] = core::array::from_fn(|i| {
            s.heads[i]
                .iter()
                .copied()
                .chain(s.packets[i].iter().copied())
                .collect()
        });
        let heads = core::array::from_fn::<_, 2, _>(|i| {
            compact_store::Commitment::decode(&s.heads[i], source::statement::limits())
                .expect("pinned public head")
        });
        let source = SourceVersionExpected::checked(
            [&images[0], &images[1]],
            [&heads[0], &heads[1]],
            source::statement::encode_digest(s.key_commitment),
            source::statement::encode_digest(s.open_commitment),
        )
        .expect("public images; NOT verified");
        let parent = source::statement::words(&[0xb7; 32])
            .collect::<Vec<_>>()
            .try_into()
            .expect("8words");
        let make_header = |label: &str| {
            let mut v = header(label);
            v.extend(source::statement::words(&[0xa7; 32]));
            v.extend(source::statement::words(&s.heads[0][8..40]));
            v.extend(s.key_commitment);
            v.try_into().expect("33header")
        };
        let registry_header = make_header("registry");
        let enrollment_header = make_header("enrollment");
        let mut h = Sha512::new();
        h.update(PROFILE_DOMAIN);
        h.update(source.version_id());
        h.update(source.state_commitment());
        for image in &images {
            h.update((image.len() as u64).to_le_bytes());
            h.update(image);
        }
        h.update(source::statement::encode_digest(s.key_commitment));
        let scope = source::statement::words(&h.finalize())
            .collect::<Vec<_>>()
            .try_into()
            .expect("16scope");
        let enrollment = [Val::from_u32(3); 4];
        let old = [Val::from_u32(5); 4];
        let command = [Val::from_u32(7); 4];
        let statement = [Val::from_u32(13); 4];
        let next = [Val::from_u32(19); 4];
        let result = [Val::from_u32(23); 4];
        // Acyclic: these independent public inputs precede every Cmd/Stmt/next/Result
        // preimage. NONE of those produced roots is fed back into context100.
        let mut ctx = Vec::new();
        ctx.extend(source::statement::words(&profile()));
        ctx.extend(source::statement::words(&[0xa7; 32]));
        ctx.extend(parent);
        ctx.extend(source::statement::words(&source.version_id()));
        ctx.extend(s.key_commitment);
        ctx.extend(s.open_commitment);
        ctx.extend(enrollment);
        ctx.extend(scope);
        ctx.extend(source::statement::words(&s.heads[0][8..40]));
        for head in &s.heads {
            ctx.extend(source::statement::words(&Sha512::digest(head)));
        }
        let context = ctx.try_into().expect("acyclic context100");
        Self {
            source,
            predicate,
            registry_header,
            enrollment_header,
            context,
            scope,
            parent,
            enrollment,
            old,
            command,
            statement,
            next,
            result,
            blind_sql: source::statement::words(&[0x61; 32])
                .collect::<Vec<_>>()
                .try_into()
                .expect("sql8"),
        }
    }
}
/// SINGLE closed factory. E IDs and Builder are never supplied by any caller.
/// Every semantic/serializer/hash/lookup use below comes from this ONE owner.
#[cfg(test)]
fn complete_build(m: &Metadata) -> Result<recipes::Built, String> {
    complete_role(m.predicate)
}
/// Role alone fixes the structural graph; no fixture or request values enter PP.
fn complete_role(predicate: bool) -> Result<recipes::Built, String> {
    let b = Builder::new(predicate);
    {
        let s = Source::new(&b);
        let controllers = controllers(&b);
        for controller in controllers {
            b.nonzero(&controller, b.c(1));
        }
        let prefix = public_values::array::<33>(&b, public_values::Group::RegistryHeader);
        let enrollment = public_values::array::<4>(&b, public_values::Group::Enrollment);
        let old = Bank::new(&b, "old", prefix, enrollment, &s);
        let new = Bank::new(&b, "new", prefix, enrollment, &s);
        canonical::bank(&b, &old, controllers);
        canonical::bank(&b, &new, controllers);
        let c = control::Command::new(&b, &old, predicate);
        let matches = s.ages.map(|age| b.mask_read(age));
        let w = predicate::Walk::new(
            &b,
            &old,
            &c,
            matches,
            public_values::array::<8>(&b, public_values::Group::BlindSql),
            predicate,
        );
        streams::source_and_enrollment(&b, &s, controllers);
        streams::command(
            &b,
            &old,
            &c,
            controllers,
            public_values::array::<8>(&b, public_values::Group::Parent),
        );
        let links = streams::statement_and_progress(&b, predicate, &old, &c, &w, controllers);
        let effect = streams::effect(&w, &links);
        control::apply(
            &b,
            &old,
            &new,
            &c,
            &effect,
            public_values::array::<8>(&b, public_values::Group::Parent),
            controllers,
        );
        streams::bank(&b, &old, false);
        streams::bank(&b, &new, true);
        streams::result(&b, predicate, &old, &new, &c, &w, &links);
        b.close();
    }
    let built = b.take();
    built.origins.require_complete(&built.pool)?;
    let pool = &built.pool;
    if !pool.errors.is_empty() {
        return Err(pool.errors.join(","));
    }
    Ok(built)
}
#[cfg(test)]
fn complete(m: &Metadata) -> Result<Pool, String> {
    Ok(complete_build(m)?.pool)
}

// Actual native security/resource assessment before private proving.
mod assessment;

// Fixed native implementation; no SQL or finality admission.
#[cfg(test)]
mod api_tests;
mod goldens;
pub(super) mod hash_backend;
mod hash_setup;
pub(super) mod hash_wire;
mod inventory_encoding;
pub(super) mod probe;
#[cfg(test)]
mod probe_tests;
pub(super) mod probe_wire;

// Independent PUBLIC branch witness/proof coverage, no runtime admission.
#[cfg(test)]
pub(super) mod owner_cases;
#[cfg(test)]
mod owner_cases_tests;

// Separate complete Stmt96 -> Cw4112 math inventory; no runtime admission.
#[cfg(test)]
mod query_mask_inventory;
