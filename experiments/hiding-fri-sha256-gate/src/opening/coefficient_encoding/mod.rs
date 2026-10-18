//! Non-admitting Source/private-query coefficient evidence; no SQL execution or network role.
mod compiler;
mod fixture;
#[cfg(test)]
mod input_formation;
#[cfg(test)]
mod tests;
use registry200_proof::coefficient_encoding::circuit as trace;
#[cfg(test)]
mod attacker;
#[cfg(test)]
use crate::backend::{Backend, Config};
use crate::{
    backend::Error,
    primitive::{Kind, PrimitiveAir, PublicStatement},
};
#[cfg(test)]
use p3_matrix::dense::RowMajorMatrix;
#[cfg(test)]
use p3_uni_stark::Proof;
use registry200_proof::coefficient_encoding::statement::{Expected, Statement};
use registry200_proof::coefficient_encoding::{Role, air::EncodingAir, wire};
impl PublicStatement for Statement {
    fn kind(&self) -> Kind {
        match self.expected.role() {
            Role::SourceAllOriginal => Kind::SourceCoefficientEncoding,
            Role::PrivateMask => Kind::PrivateMaskCoefficientEncoding,
        }
    }
    fn air(&self) -> PrimitiveAir {
        PrimitiveAir::CoefficientEncoding(Box::new(EncodingAir::new(self)))
    }
    fn public_values(&self) -> Vec<crate::backend::Val> {
        self.values()
    }
}
/// The Source proof is real and mandatory; the Key33 DTO is only independently pinned context.
#[cfg(test)]
fn prove_child_with_factory(
    e: &Expected,
    s: &Statement,
    source: Option<&Proof<Config>>,
    factory: impl FnOnce() -> Result<RowMajorMatrix<crate::backend::Val>, Error>,
) -> Result<Proof<Config>, Error> {
    s.require_expected(e)?;
    Backend::new(e.source_claim())?.verify(e.source_claim(), source.ok_or(Error::Verification)?)?;
    let backend = Backend::new(s)?;
    let proof = backend.prove_with_trace(s, factory)?;
    backend.verify(s, &proof)?;
    Ok(proof)
}
pub(crate) fn gate(mode: &str) -> Result<(), Error> {
    use std::time::Instant;
    if mode == "security" {
        let f = fixture::shape()?;
        crate::security(&f.source_statement, "public-shape-no-admission")?;
        crate::security(
            &Statement {
                expected: f.source.clone(),
                encoded: [crate::backend::Val::default(); 4],
            },
            "public-shape-no-admission",
        )?;
        return crate::security(
            &Statement {
                expected: f.query.clone(),
                encoded: [crate::backend::Val::default(); 4],
            },
            "public-shape-no-admission",
        );
    }
    if mode != "prove" {
        return Err(Error::Shape);
    }
    let total = Instant::now();
    let f = fixture::genuine()?;
    let setup_ms = total.elapsed().as_secs_f64() * 1000.;
    let started = Instant::now();
    let source_proof = registry200_proof::source::prove(
        &registry200_proof::admission::CanonicalSource::checked_claim(&f.source_statement)?,
        &f.source_witness,
    )
    .map_err(|_| Error::Verification)?;
    let source_ms = started.elapsed().as_secs_f64() * 1000.;
    let source_bytes = source_proof.into_bytes();
    let mut sizes = [0; 2];
    let mut prove_ms = [0.; 2];
    let mut verify_ms = [0.; 2];
    for (i, (e, w)) in [
        (&f.source, &f.source_encoding),
        (&f.query, &f.query_encoding),
    ]
    .into_iter()
    .enumerate()
    {
        let started = Instant::now();
        let evidence = registry200_proof::coefficient_encoding::prove(e, w, &source_bytes)
            .map_err(|_| Error::Verification)?;
        let (s, bytes) = evidence.into_parts();
        prove_ms[i] = started.elapsed().as_secs_f64() * 1000.;
        sizes[i] = bytes.len();
        let started = Instant::now();
        let decoded = wire::verify(e, &bytes)
            .map_err(|_| Error::Verification)?
            .statement()
            .clone();
        require_complete(&s, &decoded)?;
        let _opening = w.formation_opening(&decoded)?;
        verify_ms[i] = started.elapsed().as_secs_f64() * 1000.;
    }
    drop(source_bytes);
    drop(f);
    println!(
        "{}",
        serde_json::json!({"stage":"verified_private_coefficient_encodings","source_width":Role::SourceAllOriginal.width(),"query_width":Role::PrivateMask.width(),"source_pv":752,"query_pv":772,"setup_and_key_ms":setup_ms,"source_prove_verify_ms":source_ms,"child_prove_encode_ms":prove_ms,"fresh_decode_verify_and_opening_ms":verify_ms,"pair_frame_bytes":sizes,"generation_through_drop_ms":total.elapsed().as_secs_f64()*1000.,"sql_grant":false,"formation_proven":false,"key_proof_in_pair":false,"composed_128_claim":false})
    );
    Ok(())
}
fn require_complete(a: &Statement, b: &Statement) -> Result<(), Error> {
    a.require_expected(&b.expected)?;
    if a.values() != b.values() {
        return Err(Error::Shape);
    }
    Ok(())
}
