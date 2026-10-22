//! PUBLIC metadata-only endpoints, not ciphertexts claimed to encrypt a witness.
//! No evidence, native prover, private query execution or accepting result exists.
use super::*;
use crate::{
    Val,
    registry_progress::word::{self, Claims, Role},
    registry_progress::word_inventory::owner,
    two_lane_encoding::{self as encoding, data_formation as installed, statement::KeyBinding},
};
use bfv_ciphertext_formation::gold;
use p3_field::{PrimeCharacteristicRing, PrimeField64};

fn public_endpoint(components: usize) -> Vec<u8> {
    fn varint(mut n: usize, out: &mut Vec<u8>) {
        while n >= 128 {
            out.push((n as u8 & 127) | 128);
            n >>= 7;
        }
        out.push(n as u8);
    }
    let mut ciphertext = Vec::new();
    for _ in 0..components {
        let mut polynomial = vec![8, 2, 16];
        varint(product::N, &mut polynomial);
        polynomial.push(26);
        varint(product::N * 60 / 8, &mut polynomial);
        polynomial.resize(polynomial.len() + product::N * 60 / 8, 0);
        ciphertext.push(10);
        varint(polynomial.len(), &mut ciphertext);
        ciphertext.extend(polynomial);
    }
    ciphertext
}

fn expected() -> Expected {
    let (m, _) = owner::public_case(true);
    let word = word::Expected::checked(
        &m.source,
        Role::Predicate,
        [0xa7; 32],
        m.parent
            .into_iter()
            .flat_map(|v| u32::try_from(v.as_canonical_u64()).unwrap().to_le_bytes())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        m.enrollment,
        Claims {
            old: m.old,
            command: m.command,
            statement: m.statement,
            next: m.next,
            result: m.result,
            blind_sql: m.blind_sql,
        },
    )
    .unwrap();
    let key = KeyBinding::new(
        m.source.statement().heads[0][8..24].try_into().unwrap(),
        [0x91; 16],
        7,
        [0x95; 32],
        [0; 32],
    )
    .unwrap();
    let child = encoding::statement::Statement {
        expected: encoding::statement::Expected::source_version(&m.source, key).unwrap(),
        encoded: [Val::ONE; 4],
    };
    let request = gold::data::Request::checked([0x93; 32], public_endpoint(2)).unwrap();
    let data = installed::Expected::checked(&request, &child).unwrap();
    let request =
        gold::Request::checked([0x94; 32], [public_endpoint(2), public_endpoint(2)]).unwrap();
    Expected::checked(&word, &data, &request, [Val::TWO; 4], public_endpoint(3)).unwrap()
}

#[test]
fn actual_closed_airs_report_five_native_arguments_and_original_lookup_counts() {
    let report = analyze(&expected(), 60).unwrap();
    let expected = [
        (Relation::SourceVersion, 10, None),
        (Relation::VersionEncoding, 10, None),
        (Relation::DataFormation, 12, Some((243, 2))),
        (Relation::PredicateWord, 10, Some((98, 5))),
        (Relation::QueryFormation, 12, Some((248, 2))),
    ];
    for (component, (relation, committed_log, lookup)) in report.components().iter().zip(expected) {
        let bound = component.bound();
        let params = bound.parameters();
        assert_eq!(component.relation(), relation);
        assert_eq!(bound.committed_log(), committed_log);
        assert_eq!(bound.logup(), lookup);
        assert_eq!(bound.analysis_m(), 3);
        assert!(params.num_constraints > 0);
        assert_eq!(
            params.num_quotient_chunks,
            if matches!(
                relation,
                Relation::SourceVersion | Relation::VersionEncoding
            ) {
                16
            } else {
                8
            }
        );
        assert!(bound.union_bits() > 235.0);
        assert_eq!(bound.terms().len(), if lookup.is_some() { 6 } else { 5 });
        eprintln!(
            "closed_classical_air relation={relation:?} committed_log={committed_log} constraints={} degree={} chunks={} openings={} original_logup={lookup:?} rbr_sum_bits={} terms={:?} proof=false sql=false",
            params.num_constraints,
            params.air_max_constraint_degree,
            params.num_quotient_chunks,
            params.num_batched_functions,
            bound.union_bits(),
            bound.terms(),
        );
    }
    assert_eq!(
        report.components()[4]
            .bound()
            .parameters()
            .num_batched_functions,
        2327
    );
    assert_eq!(report.pit_single_bits(), 306);
    print_report(&report);
}

fn print_report(report: &Report) {
    eprintln!(
        "closed_classical_composition log2_budget={} bcs_algebraic_bits={} bcs_collision_bits={} pit_bits={} conditional_sum_bits={} ideal_transcript_mapping_unproven=true binding_terms_excluded=true cryptographic_security_assessed=false sql_accepted=false",
        report.log2_query_budget(),
        report.bcs_algebraic_bits(),
        report.bcs_collision_bits(),
        report.pit_budget_bits(),
        report.conditional_error_bits(),
    );
}

#[test]
fn larger_adaptive_budget_charges_all_five_bcs_terms_and_the_pit_attempts() {
    let report = analyze(&expected(), 40).unwrap();
    let mut previous = f64::INFINITY;
    for b in [40, 60, 64, 120] {
        let current = compose(report.components.clone(), b).unwrap();
        // Independent probability-space expression: five full BCS collision
        // terms, five algebraic terms, and one adaptive eighteen-point PIT term.
        let q = 2.0f64.powi(b as i32);
        let algebraic: f64 = report
            .components()
            .iter()
            .map(|c| q * 2.0f64.powf(-c.bound().union_bits()))
            .sum();
        let collisions = 15.0 * (q * q + 1.0) / 2.0f64.powi(255);
        let pit = q * 2.0f64.powi(-306);
        let reported = 2.0f64.powf(-current.conditional_error_bits());
        assert!(reported >= algebraic + collisions + pit);
        assert!(reported < 4.1 * (algebraic + collisions + pit));
        assert!(current.conditional_error_bits() < previous);
        assert_eq!(current.pit_budget_bits(), 306.0 - f64::from(b));
        if b == 64 {
            assert!(
                current.conditional_error_bits() < 128.0,
                "a fixed-budget error ceiling must not be relabelled 128 workbits"
            );
        }
        previous = current.conditional_error_bits();
        print_report(&current);
    }
    assert!(matches!(
        compose(report.components.clone(), 121),
        Err(Error::Budget)
    ));
    assert!(matches!(analyze(&expected(), u32::MAX), Err(Error::Budget)));
}

#[test]
fn the_actual_product_geometry_supports_the_coarse_306_bit_pit_lemma() {
    assert_eq!(product::N, 4096);
    assert_eq!(product::POINTS, 18);
    // The smallest original Q field is the worst case, not a P intermediate.
    assert_eq!(product::QP.iter().min().copied(), Some(1_073_668_097));
    let degree = (2 * product::N - 2) as u128;
    let smallest = u128::from(*product::QP.iter().min().unwrap());
    let denominator = 1u128 << 17;
    assert!(degree * (denominator + 1) < smallest);
    assert!(degree * denominator * (denominator + 1) < 1u128 << 64);
    assert_eq!(product_single_bits().unwrap(), 306);
}

#[test]
fn fixed_five_transcript_manifest_keeps_real_salt_geometry_and_opening_order() {
    let expected = expected();
    let report = analyze(&expected, 60).unwrap();
    let manifests = super::super::transcript::inspect(&expected).unwrap();
    let widths: [&[usize]; 5] = [
        &[14, 7170, 224],
        &[14, 1665, 224],
        &[14, 521, 112, 672, 419],
        &[14, 577, 112, 718, 184],
        &[14, 425, 112, 549, 429],
    ];
    // Reviewed public seed/geometry snapshots, captured independently of proofs.
    let snapshots = [
        "406e2791ce0b1198980fda765c99e528903723aa3b8977a9ce7e2cb333fe933a",
        "378d90a66c4e82ec06b8dbe84b7b3d6538bc6aafc3a50d1393f1428ee3ff1977",
        "8536f9022089addb76a956eaefdcdf269b3cd01e4a004d6692739c840925699e",
        "9eab76dfbb11338eb63ff875189798ce1d3768d60bc96c5e3d6984db5e3d7119",
        "7884b9c9949e5ce746cc46f482928d87d1fef2b142c8b84322b3d64242e2d742",
    ];
    for (i, manifest) in manifests.iter().enumerate() {
        assert_eq!(hex(&manifest.snapshot_digest()), snapshots[i]);
        let leafs: Vec<_> = manifest
            .commitments()
            .iter()
            .map(|g| g.salted_leaf_width())
            .collect();
        assert_eq!(leafs, widths[i]);
        assert_eq!(manifest.fri_salted_leaf_width(), 14);
        assert_eq!(manifest.fri_matrix_logs().last(), Some(3));
        let count: usize = manifest
            .pcs_shape()
            .claimed_evaluation_counts
            .iter()
            .flatten()
            .flatten()
            .sum();
        assert_eq!(
            count,
            report.components()[i]
                .bound()
                .parameters()
                .num_batched_functions
        );
        assert_eq!(
            manifest.fri_shape(),
            report.components()[i].bound().fri_shape()
        );
        let name: &[u8] = if i < 2 {
            b"p3-uni-stark"
        } else {
            b"p3-batch-stark"
        };
        assert_eq!(&manifest.stark().protocol_id()[1..1 + name.len()], name);
        assert!(
            manifest
                .stark()
                .observed_fields()
                .iter()
                .all(|v| v.as_canonical_u64() < (1u64 << 56))
        );
        eprintln!(
            "closed_transcript_manifest relation={:?} snapshot_sha256={} leaf_widths={leafs:?} stark_pattern={} pcs_pattern={} fri_pattern={} lde_log={} proof=false sql=false",
            report.components()[i].relation(),
            hex(&manifest.snapshot_digest()),
            hex(manifest.stark().pattern_hash()),
            hex(manifest.pcs().pattern_hash()),
            hex(manifest.fri().pattern_hash()),
            manifest.lde_log()
        );
    }
    assert_ne!(
        manifests[0].snapshot_digest(),
        manifests[1].snapshot_digest()
    );
    assert_ne!(
        manifests[2].snapshot_digest(),
        manifests[4].snapshot_digest()
    );
    // DATA/Query share the batch message-count pattern but bind distinct widths.
    assert_eq!(
        manifests[2].stark().pattern_hash(),
        manifests[4].stark().pattern_hash()
    );
    assert_ne!(
        manifests[2].stark().instance_label(),
        manifests[4].stark().instance_label()
    );
}

fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write;
    let mut text = String::new();
    for byte in bytes {
        write!(&mut text, "{byte:02x}").unwrap();
    }
    text
}
