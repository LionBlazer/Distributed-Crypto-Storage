//! Public, non-secret examples at this fixed protocol's owning boundary.
use super::*;
use p3_air::{Air, AirBuilder, BaseAir, BoundaryEnd, BoundaryPublic, WindowAccess};
use p3_bus::{BusActivation, BusDirection, BusInteractionBuilder, BusName};
use p3_challenger::{CanSample, HashChallenger, SerializingChallenger64};
use p3_field::PrimeCharacteristicRing;
use p3_lookup::{Count, IndexedLookupBuilder, InteractionBuilder, TraceWindow};
use p3_matrix::dense::RowMajorMatrix;
use p3_multi_stark::{
    ProverInstance, ProverInstances, VerifierInstance, VerifierInstances, prove_with_security,
    setup, verify_with_security,
};
use p3_sumcheck::layout::Table;
use p3_symmetric::CryptographicHasher;
use sha2::{Digest, Sha512};
use std::sync::atomic::{AtomicUsize, Ordering};

fn domains() -> Domains {
    Domains::new(
        b"DCS/NTT-WITNESS/v1/MERKLE-LEAF/LE64/",
        b"DCS/NTT-WITNESS/v1/MERKLE-NODE/LE64/",
        b"DCS/NTT-WITNESS/v1/FIAT-SHAMIR/BYTES/",
        b"DCS/NTT-WITNESS-PROOF/v1/statement/",
    )
    .unwrap()
}
const H: usize = 1024;
#[derive(Clone, Copy)]
struct Current {
    pp: bool,
    square: bool,
}
impl BaseAir<Val> for Current {
    fn width(&self) -> usize {
        1
    }
    fn preprocessed_width(&self) -> usize {
        usize::from(self.pp)
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val>> {
        self.pp
            .then(|| RowMajorMatrix::new(vec![Val::from_u8(7); H], 1))
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    fn num_public_values(&self) -> usize {
        1
    }
}
impl<AB: AirBuilder<F = Val>> Air<AB> for Current {
    fn eval(&self, b: &mut AB) {
        let x: AB::Expr = b.main().current_slice()[0].into();
        let public: AB::Expr = b.public_values()[0].into();
        let difference = x - public;
        if self.square {
            b.assert_zero(difference.clone() * difference);
        } else {
            b.assert_zero(difference);
        }
        if self.pp {
            let fixed: AB::Expr = b.preprocessed().current_slice()[0].into();
            b.assert_zero(fixed - Val::from_u8(7));
        }
    }
}
fn instances<'a>(
    air: &'a Current,
    vk: &'a p3_multi_stark::VerifyingKey<Config>,
    log: usize,
    public: &'a [Val],
) -> VerifierInstances<'a, Config, Current> {
    VerifierInstances::new(vec![VerifierInstance::new(air, vk, log, public)])
}
fn config(air: &Current) -> Config {
    config_for(&[AirSpec::new(air, H.ilog2() as usize)], domains())
        .unwrap()
        .0
}

#[test]
fn domain_labels_reject_empty_equal_and_prefix_aliases_in_every_position() {
    let good = [b"L/".as_slice(), b"N/", b"T/", b"S/"];
    for i in 0..4 {
        let mut labels = good;
        labels[i] = b"";
        assert_eq!(
            Domains::new(labels[0], labels[1], labels[2], labels[3]),
            Err(Error::InvalidDomains)
        );
        for j in 0..4 {
            if i == j {
                continue;
            }
            let mut labels = good;
            labels[j] = labels[i];
            assert_eq!(
                Domains::new(labels[0], labels[1], labels[2], labels[3]),
                Err(Error::InvalidDomains)
            );
            labels[i] = b"shared/";
            labels[j] = b"shared/suffix/";
            assert_eq!(
                Domains::new(labels[0], labels[1], labels[2], labels[3]),
                Err(Error::InvalidDomains)
            );
        }
    }
    assert!(Domains::new(good[0], good[1], good[2], good[3]).is_ok());
}

#[test]
fn hash_interfaces_retain_all_eight_little_endian_words_and_distinct_domains() {
    let d = domains();
    let input = [0x0807_0605_0403_0201u64, 0xfedc_ba98_7654_3210];
    let mut independent = Sha512::new();
    independent.update(d.leaf());
    for word in input {
        independent.update(word.to_le_bytes());
    }
    let expected: [u8; 64] = independent.finalize().into();
    let actual = d.leaf_hasher().hash_iter(input);
    let bytes: Vec<_> = actual.into_iter().flat_map(u64::to_le_bytes).collect();
    assert_eq!(bytes, expected);
    assert!(bytes[32..].iter().any(|&b| b != 0));
    assert_ne!(actual, d.node_hasher().hash_iter(input));
    assert_ne!(
        d.transcript_hasher().hash_iter([1, 2, 3]),
        sha512(&[1, 2, 3])
    );
    // Independent published SHA512("abc") vector checks the complete byte interface.
    assert_eq!(
        sha512(b"abc"),
        [
            0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20,
            0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6,
            0x4b, 0x55, 0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba,
            0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
            0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
        ]
    );
}
fn samples(mut c: Challenger) -> [Challenge; 2] {
    [c.sample(), c.sample()]
}
#[test]
fn exact_legacy_seed_and_complete_last_wire_bytes_control_the_challenger() {
    let c = config(&Current {
        pp: false,
        square: false,
    });
    let profile = [0x7bu8; 64];
    let request = [0x23u8; 333];
    let output = [0x91u8; 277];
    // Reconstruct the existing NTT seed independently of Config::challenger.
    let mut initial = b"DCS/NTT-WITNESS-PROOF/v1/statement/".to_vec();
    initial.extend(profile);
    initial.extend(Sha512::digest(request));
    initial.extend(Sha512::digest(output));
    let legacy =
        SerializingChallenger64::new(HashChallenger::new(initial, domains().transcript_hasher()));
    let expected = samples(legacy);
    assert_eq!(samples(c.challenger(profile, &request, &output)), expected);
    let mut changed = request;
    changed[332] ^= 1;
    assert_ne!(samples(c.challenger(profile, &changed, &output)), expected);
    let mut changed = output;
    changed[276] ^= 1;
    assert_ne!(samples(c.challenger(profile, &request, &changed)), expected);
    let mut changed = profile;
    changed[63] ^= 1;
    assert_ne!(samples(c.challenger(changed, &request, &output)), expected);
}

struct Probe {
    width: usize,
    preprocessed_width: usize,
    public_values: usize,
    evals: AtomicUsize,
}
impl BaseAir<Val> for Probe {
    fn width(&self) -> usize {
        self.width
    }
    fn preprocessed_width(&self) -> usize {
        self.preprocessed_width
    }
    fn num_public_values(&self) -> usize {
        self.public_values
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
}
impl<AB: AirBuilder<F = Val>> Air<AB> for Probe {
    fn eval(&self, b: &mut AB) {
        self.evals.fetch_add(1, Ordering::SeqCst);
        b.assert_zero(AB::Expr::ZERO);
    }
}
#[test]
fn invalid_and_overflowing_metadata_is_rejected_before_symbolic_width_allocation() {
    let probe = Probe {
        width: usize::MAX,
        preprocessed_width: 0,
        public_values: 0,
        evals: AtomicUsize::new(0),
    };
    assert!(matches!(
        config_for(&[AirSpec::new(&probe, 4)], domains()),
        Err(Error::InvalidShape)
    ));
    assert_eq!(probe.evals.load(Ordering::SeqCst), 0);
    let probe = Probe {
        width: 1,
        preprocessed_width: 0,
        public_values: 0,
        evals: AtomicUsize::new(0),
    };
    for log in [0, 3, usize::BITS as usize] {
        assert!(matches!(
            config_for(&[AirSpec::new(&probe, log)], domains()),
            Err(Error::InvalidShape)
        ));
    }
    let log = usize::BITS as usize - 1;
    assert!(matches!(
        config_for(
            &[AirSpec::new(&probe, log), AirSpec::new(&probe, log)],
            domains()
        ),
        Err(Error::InvalidShape)
    ));
    assert!(matches!(
        config_for(&[AirSpec::new(&probe, 32)], domains()),
        Err(Error::Schedule)
    ));
    assert_eq!(probe.evals.load(Ordering::SeqCst), 0);
    assert!(matches!(
        config_for::<Probe>(&[], domains()),
        Err(Error::InvalidShape)
    ));
    // Logical cell counts and PCS dimensions alone cannot bound SDK vectors.
    let symbolic_limit =
        isize::MAX as usize / std::mem::size_of::<p3_air::symbolic::SymbolicVariable<Val>>();
    for (width, preprocessed_width, public_values) in [
        (1, 0, usize::MAX),
        (1, 0, symbolic_limit + 1),
        (symbolic_limit / 2 + 1, 0, 0),
        (1, symbolic_limit / 2 + 1, 0),
        (1, usize::MAX, 0),
    ] {
        let probe = Probe {
            width,
            preprocessed_width,
            public_values,
            evals: AtomicUsize::new(0),
        };
        assert!(matches!(
            config_for(&[AirSpec::new(&probe, 4)], domains()),
            Err(Error::InvalidShape)
        ));
        assert_eq!(probe.evals.load(Ordering::SeqCst), 0);
    }
}

#[derive(Clone, Copy, Debug)]
enum Unsupported {
    Next,
    PrepNext,
    HiddenNext,
    HiddenPrepNext,
    HiddenLookupNext,
    Periodic,
    Boolean,
    Boundary,
    Local,
    Exclusive,
    Indexed,
    Binary,
}
struct UnsupportedAir(Unsupported);
const BOUNDARY: [BoundaryPublic; 1] = [BoundaryPublic::new(0, BoundaryEnd::First, 0)];
impl BaseAir<Val> for UnsupportedAir {
    fn width(&self) -> usize {
        1
    }
    fn preprocessed_width(&self) -> usize {
        1
    }
    fn num_public_values(&self) -> usize {
        1
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        if matches!(self.0, Unsupported::Next) {
            vec![0]
        } else {
            vec![]
        }
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        if matches!(self.0, Unsupported::PrepNext) {
            vec![0]
        } else {
            vec![]
        }
    }
    fn num_periodic_columns(&self) -> usize {
        usize::from(matches!(self.0, Unsupported::Periodic))
    }
    fn assumes_boolean_trace(&self) -> bool {
        matches!(self.0, Unsupported::Boolean)
    }
    fn public_boundary_io(&self) -> &[BoundaryPublic] {
        if matches!(self.0, Unsupported::Boundary) {
            &BOUNDARY
        } else {
            &[]
        }
    }
}
impl<AB> Air<AB> for UnsupportedAir
where
    AB: InteractionBuilder<F = Val> + IndexedLookupBuilder + BusInteractionBuilder,
{
    fn eval(&self, b: &mut AB) {
        let x: AB::Expr = b.main().current_slice()[0].into();
        let public: AB::Expr = b.public_values()[0].into();
        b.assert_zero(x.clone() - public);
        match self.0 {
            Unsupported::HiddenNext => {
                let next: AB::Expr = b.main().next_slice()[0].into();
                b.assert_zero(next - x);
            }
            Unsupported::HiddenPrepNext => {
                let next: AB::Expr = b.preprocessed().next_slice()[0].into();
                b.assert_zero(next - x);
            }
            Unsupported::HiddenLookupNext => {
                let next: AB::Expr = b.main().next_slice()[0].into();
                b.push_interaction("invalid-next", [next], Count::from(1));
            }
            Unsupported::Local => b.push_local_interaction([(vec![x], Count::from(1))]),
            Unsupported::Exclusive => b.push_exclusive_interaction(
                "exclusive",
                [(AB::Expr::ONE, Count::from(1), vec![x])],
            ),
            Unsupported::Indexed => b.push_indexed_table("index", TraceWindow::Main, [0]),
            Unsupported::Binary => b.push_bus_interaction(
                BusName::new("binary"),
                BusDirection::Push,
                [x],
                BusActivation::Always,
            ),
            _ => {}
        }
    }
}
#[test]
fn unsupported_declarations_and_undeclared_next_leaves_fail_closed() {
    for mode in [
        Unsupported::Next,
        Unsupported::PrepNext,
        Unsupported::HiddenNext,
        Unsupported::HiddenPrepNext,
        Unsupported::HiddenLookupNext,
        Unsupported::Periodic,
        Unsupported::Boolean,
        Unsupported::Boundary,
        Unsupported::Local,
        Unsupported::Exclusive,
        Unsupported::Indexed,
        Unsupported::Binary,
    ] {
        let air = UnsupportedAir(mode);
        assert!(
            matches!(
                config_for(&[AirSpec::new(&air, 10)], domains()),
                Err(Error::UnsupportedAir)
            ),
            "{mode:?}"
        );
    }
}

#[test]
fn nonzero_public_values_with_and_without_preprocessing_have_real_sdk_proofs() {
    for pp in [false, true] {
        let air = Current { pp, square: false };
        let (c, plan) = config_for(&[AirSpec::new(&air, 10)], domains()).unwrap();
        assert_eq!(plan.main_cells, H);
        assert_eq!(plan.main_pcs.initial_claims, 1);
        assert_eq!(plan.preprocessed_pcs.is_some(), pp);
        let public = [Val::from_u8(17)];
        let (pk, vk) = setup(
            &c,
            &[&air],
            &mut c.challenger([5; 64], b"public-input", b"17"),
        )
        .unwrap();
        let vi = || VerifierInstances::new(vec![VerifierInstance::new(&air, &vk, 10, &public)]);
        let report = assess(&c, &vi()).unwrap();
        assert!(report.security_bits().unwrap() >= POLICY_BITS as f64);
        assert!(report.unassessed_components().is_empty());
        assert!(
            report
                .terms()
                .iter()
                .any(|t| t.label == "commitment-and-transcript-collision")
        );
        let trace = RowMajorMatrix::new(vec![public[0]; H], 1);
        let proof = prove_with_security(
            &c,
            ProverInstances::new(vec![ProverInstance::new(
                &air,
                Table::new(trace.transpose()),
                &pk,
                &public,
            )]),
            0,
            POLICY_BITS,
            &mut c.challenger([5; 64], b"public-input", b"17"),
        )
        .unwrap();
        verify_with_security(
            &c,
            vi(),
            &proof,
            0,
            POLICY_BITS,
            &mut c.challenger([5; 64], b"public-input", b"17"),
        )
        .unwrap();
        let wrong = [Val::from_u8(18)];
        let vi = VerifierInstances::new(vec![VerifierInstance::new(&air, &vk, 10, &wrong)]);
        assert!(
            verify_with_security(
                &c,
                vi,
                &proof,
                0,
                POLICY_BITS,
                &mut c.challenger([5; 64], b"public-input", b"18")
            )
            .is_err()
        );
    }
}

#[test]
fn assessment_uses_actual_constraints_and_rejects_foreign_shapes_before_sdk() {
    let air = Current {
        pp: false,
        square: false,
    };
    let c = config(&air);
    let (_, vk) = setup(&c, &[&air], &mut c.challenger([6; 64], b"r", b"o")).unwrap();
    let public = [Val::from_u8(17)];
    let original = assess(&c, &instances(&air, &vk, 10, &public)).unwrap();
    let changed = Current {
        pp: false,
        square: true,
    };
    let actual = assess(&c, &instances(&changed, &vk, 10, &public)).unwrap();
    let direct =
        p3_multi_stark::security_report(&c, &instances(&changed, &vk, 10, &public)).unwrap();
    let terms = |r: &MultiStarkSecurityReport| {
        r.terms()
            .iter()
            .map(|t| (t.label, t.component, t.bits.bits()))
            .collect::<Vec<_>>()
    };
    assert_eq!(terms(&actual), terms(&direct));
    assert_ne!(terms(&original), terms(&actual));
    let pp = Current {
        pp: true,
        square: false,
    };
    assert!(matches!(
        assess(&c, &instances(&pp, &vk, 10, &public)),
        Err(Error::InvalidShape)
    ));
    assert!(matches!(
        assess(&c, &instances(&air, &vk, 9, &public)),
        Err(Error::InvalidShape)
    ));
    let missing = VerifierInstances::new(vec![VerifierInstance::new(&air, &vk, 10, &[])]);
    assert!(matches!(assess(&c, &missing), Err(Error::InvalidShape)));
}
