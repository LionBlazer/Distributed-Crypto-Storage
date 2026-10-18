//! PUBLIC NONSECRET actual signed history and actual Owner BFV composition. No SQL/finality admission.
use super::*;
use bfv_ciphertext_formation::Prerequisites;
use bfv_query_core::{Geometry, KeyScope, Owner};
use p3_field::PrimeCharacteristicRing;
use std::time::Instant;

pub(super) fn gate(mode: &str) -> Result<(), Error> {
    if !matches!(mode, "security" | "prove") {
        return Err(Error::Shape);
    }
    if mode == "security" {
        let (encoded, w) = encoding::conditional_formation_shape()?;
        let (owner, setup) = Owner::generate(Geometry::Rows16).map_err(|_| Error::Shape)?;
        let handle = owner
            .key_anchor(
                &setup,
                KeyScope {
                    database: encoded.formation_source().heads[0][8..24]
                        .try_into()
                        .unwrap(),
                    bfv_key_domain: [0x71; 16],
                    epoch: 1,
                },
            )
            .map_err(|_| Error::Shape)?;
        let ciphertext = handle
            .encrypt_encoded_coefficients(&setup, &w)
            .map_err(|_| Error::Shape)?;
        // Public zero-key mathematical SHAPE fixture only; no proof or operational Owner mint.
        let key = bfv_key_transform::ProverWitness::new(
            zeroize::Zeroizing::new(vec![0; 8192]),
            [1; 4],
            [2; 4],
        )?
        .statement(bfv_key_transform::SetupDescriptor {
            database: encoded.formation_source().heads[0][8..24]
                .try_into()
                .unwrap(),
            key_domain: [0x71; 16],
            public_setup_digest: bfv_basis_convolution::setup_digest(),
            key_epoch: 1,
        });
        let bases = core::array::from_fn(|i| bfv_basis_convolution::Statement {
            expected: bfv_basis_convolution::Expected::new(
                key.clone(),
                &bfv_basis_convolution::parameters().to_bytes(),
                &ciphertext,
                encoded.formation_source().request,
                i,
            )
            .unwrap(),
            result: [crate::backend::Val::ZERO; 4],
        });
        let expected = Expected::new(encoded, bases)?;
        let statement = bfv_ciphertext_formation::Statement {
            expected: expected.mathematical,
            full_setup_id: handle.public_anchor().full_setup_id(),
            noise: [crate::backend::Val::ZERO; 4],
        };
        crate::security(&statement, "public-nonsecret-registry200-formation-shape")?;
        return Ok(());
    }
    let generation = Instant::now();
    let product = super::super::journal::formation_input(1)?;
    let produced = produce_from_encoding(product, generation)?;
    let start = Instant::now();
    let setup = PublicSetup::from_bytes(&produced.setup_bytes).map_err(|_| Error::Shape)?;
    let p = produced.prerequisites();
    let _ = super::verify(
        &setup,
        &produced.anchor,
        &produced.expected,
        &produced.encoding_frame,
        &p,
        &produced.evidence,
    )?;
    println!(
        "{}",
        serde_json::json!({"stage":"verified_registry200_signed_history_actual_owner_formation","generation_ms":produced.generation_ms,"fresh_setup_and_verification_ms":start.elapsed().as_secs_f64()*1000.0,"setup_bytes":produced.setup_bytes.len(),"ciphertext_bytes":produced.ciphertext.len(),"encoding_frame_bytes":produced.encoding_frame.len(),"key_frame_bytes":produced.key.len(),"basis_frame_bytes":produced.frames.each_ref().map(Vec::len),"formation_frame_bytes":produced.evidence.len(),"accepted_journal_history":true,"live_sql_grant":false,"agreed_finality":false,"evaluation_key_consistency_proven":false,"composed_128_claim":false})
    );
    Ok(())
}
/// Public-only product after all private Owner/handle/job material has been dropped.
pub(super) struct PublicProduct {
    pub expected: Expected,
    pub setup_bytes: Vec<u8>,
    pub anchor: BfvKeyAnchor,
    pub ciphertext: Vec<u8>,
    pub encoding_frame: Vec<u8>,
    pub key: Vec<u8>,
    pub frames: [Vec<u8>; 5],
    pub evidence: Vec<u8>,
    pub generation_ms: f64,
}
impl PublicProduct {
    pub fn prerequisites(&self) -> Prerequisites<'_> {
        Prerequisites {
            key: &self.key,
            bases: self.frames.each_ref().map(Vec::as_slice),
        }
    }
}
pub(super) fn produce_from_encoding(
    product: super::super::journal::FormationEncodingProduct,
    generation: Instant,
) -> Result<PublicProduct, Error> {
    let (encoded, encoding_frame, opening, w) = (
        product.statement,
        product.frame,
        product.opening,
        product.coefficients,
    );
    let (owner, setup) = Owner::generate(Geometry::Rows16).map_err(|_| Error::Shape)?;
    let setup_bytes = setup.to_bytes().map_err(|_| Error::Shape)?;
    let handle = owner
        .key_anchor(
            &setup,
            KeyScope {
                database: encoded.formation_source().heads[0][8..24]
                    .try_into()
                    .unwrap(),
                bfv_key_domain: [0x71; 16],
                epoch: 1,
            },
        )
        .map_err(|_| Error::Shape)?;
    let anchor = handle.public_anchor().clone();
    let ciphertext = handle
        .encrypt_encoded_coefficients(&setup, &w)
        .map_err(|_| Error::Shape)?;
    let request = encoded.formation_source().request;
    let mut job = handle
        .basis_job(&setup, request, &ciphertext)
        .map_err(|_| Error::Shape)?;
    let key = job
        .prove_key()
        .map_err(|_| Error::Verification)?
        .as_bytes()
        .to_vec();
    let mut frames: [Vec<u8>; 5] = core::array::from_fn(|_| Vec::new());
    let mut claims = Vec::with_capacity(5);
    for (i, frame) in frames.iter_mut().enumerate() {
        *frame = job
            .prove_next_basis()
            .map_err(|_| Error::Verification)?
            .into_bytes();
        claims.push(
            setup
                .verify_basis_convolution(&anchor, request, &ciphertext, i, &key, frame.as_slice())
                .map_err(|_| Error::Verification)?
                .statement()
                .clone(),
        );
    }
    let expected = Expected::new(encoded, claims.try_into().ok().unwrap())?;
    let p = Prerequisites {
        key: &key,
        bases: frames.each_ref().map(Vec::as_slice),
    };
    let mut formation = job.into_formation(opening).map_err(|_| Error::Shape)?;
    let evidence = super::prove(&expected, &encoding_frame, &mut formation, &p)?.into_bytes();
    drop(formation);
    drop(handle);
    drop(owner);
    drop(setup);
    drop(w);
    let generation_ms = generation.elapsed().as_secs_f64() * 1000.0;
    Ok(PublicProduct {
        expected,
        setup_bytes,
        anchor,
        ciphertext,
        encoding_frame,
        key,
        frames,
        evidence,
        generation_ms,
    })
}
use fhe_traits::Serialize;
