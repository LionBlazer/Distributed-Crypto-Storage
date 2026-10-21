//! Unconditional ORIGINAL Data regression captured natively BEFORE range extraction.
//! No MAIN/full-PP matrix/commitment/proof/SDK private fixture is constructed.
use super::{HEIGHT, LOG_HEIGHT, PP_WIDTH, WIDTH, air::ProgramAir, descriptor::Descriptor, pp};
use crate::gold::{
    Val, data,
    relation::{ExpectedRef, RelationKind},
    wire,
};
use bfv_hiding_stark::{Challenge, Challenger, Pcs};
use p3_air::{BaseAir, symbolic::AirLayout};
use p3_batch_stark::symbolic::{
    get_log_num_quotient_chunks_for_domain, get_max_constraint_degree, get_symbolic_constraints,
};
use p3_commit::{PolynomialSpace, UnivariateStarkPcs};
use p3_field::{PrimeCharacteristicRing, PrimeField64, coset::TwoAdicMultiplicativeCoset};
use p3_lookup::{LogUpGadget, Lookups};
use sha2::{Digest, Sha256};
struct SnapshotHash {
    hash: Sha256,
    bytes: usize,
}
impl SnapshotHash {
    fn new() -> Self {
        let mut hash = Sha256::new();
        hash.update(b"DCS/research/dense-data/original-ordered/postcard-p3-0.8/v1");
        Self { hash, bytes: 0 }
    }
}
impl postcard::ser_flavors::Flavor for SnapshotHash {
    type Output = ([u8; 32], usize);
    fn try_push(&mut self, v: u8) -> postcard::Result<()> {
        self.try_extend(&[v])
    }
    fn try_extend(&mut self, bytes: &[u8]) -> postcard::Result<()> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .filter(|n| *n <= 64 * 1024 * 1024)
            .ok_or(postcard::Error::SerializeBufferFull)?;
        self.hash.update(bytes);
        Ok(())
    }
    fn finalize(self) -> postcard::Result<Self::Output> {
        Ok((self.hash.finalize().into(), self.bytes))
    }
}
fn hex(bytes: impl AsRef<[u8]>) -> String {
    use core::fmt::Write;
    let mut v = String::new();
    for b in bytes.as_ref() {
        write!(&mut v, "{b:02x}").unwrap()
    }
    v
}
fn expected() -> data::Expected {
    let request =
        data::Request::checked([0xc7; 32], crate::gold::tests::pair_snapshot_ciphertext(0))
            .unwrap();
    data::Expected::checked(
        request,
        [0xd7; 64],
        [[Val::from_u8(9); 8], [Val::from_u8(10); 8]],
        [[Val::from_u8(11); 4], [Val::from_u8(12); 4]],
    )
    .unwrap()
}
#[test]
fn ordered_data_constraints_lookups_and_full_preprocessing_snapshot() {
    let expected = expected();
    let air = ProgramAir::data(expected.clone()).unwrap();
    assert_eq!(
        (HEIGHT, WIDTH, PP_WIDTH, air.num_public_values()),
        (8192, 512, 272, 32)
    );
    let domain = TwoAdicMultiplicativeCoset::<Val>::new(Val::ONE, LOG_HEIGHT).unwrap();
    let layout = AirLayout::from_air(&air);
    let gadget = LogUpGadget::new();
    let zk = usize::from(<Pcs as UnivariateStarkPcs<Challenge, Challenger>>::ZK);
    assert_eq!(zk, 1);
    let original = Lookups::<Val>::from_air::<Challenge, _>(&air);
    let log = get_log_num_quotient_chunks_for_domain::<Val, Challenge, _, _>(
        &air, layout, domain, &original, zk, &gadget,
    );
    let budget = (1usize << log) + 1 - zk;
    let packed = original.clone().pack_same_bus_with_degree(budget, |l| {
        gadget.constraint_degree_with_transition(l, domain.transition_degree_multiple())
    });
    assert_eq!(
        get_log_num_quotient_chunks_for_domain::<Val, Challenge, _, _>(
            &air, layout, domain, &packed, zk, &gadget
        ),
        log
    );
    let (base, ext) =
        get_symbolic_constraints::<Val, Challenge, _, _>(&air, layout, &packed, &gadget);
    let counts = [base.len(), ext.len(), original.len(), packed.len()];
    assert_eq!(counts, [1408, 46, 128, 43]);
    let degree =
        get_max_constraint_degree::<Val, Challenge, _, _>(&air, layout, HEIGHT, &packed, &gadget);
    let (digest, symbolic_bytes) =
        postcard::serialize_with_flavor(&(base, ext, original, packed), SnapshotHash::new())
            .unwrap();
    // The actual symbolic DAG is dead before streaming PP. Only one row272 exists.
    let descriptor = Descriptor::new(ExpectedRef::Data(&expected)).unwrap();
    let mut pp_hash = Sha256::new();
    pp_hash.update(b"DCS/research/dense-data/original-full-PP/LE64/v1");
    for n in [HEIGHT, PP_WIDTH] {
        pp_hash.update((n as u64).to_le_bytes())
    }
    for row in 0..HEIGHT {
        for x in pp::row(&descriptor, row).unwrap() {
            pp_hash.update(x.as_canonical_u64().to_le_bytes())
        }
    }
    let mut pv = Sha256::new();
    pv.update(b"DCS/research/dense-data/original-PUBLIC32/LE64/v1");
    pv.update((expected.values().len() as u64).to_le_bytes());
    for x in expected.values() {
        pv.update(x.as_canonical_u64().to_le_bytes())
    }
    // ROOT r3 before-extraction receipt 651DF4BF...F1A2, immutable required-goldens.
    // No first-capture or fallback branch is permitted after extraction.
    assert_eq!(
        (degree, 1usize << (log + zk), symbolic_bytes),
        (4, 8, 552656)
    );
    let actual = [
        hex(digest),
        hex(pp_hash.finalize()),
        hex(pv.finalize()),
        hex(data::profile_digest()),
        hex(wire::profile_for(RelationKind::Data)),
        hex(Sha256::digest(expected.request().bytes())),
        hex(expected.binding()),
    ];
    assert_eq!(
        actual,
        [
            "08ca9718d797ee5041e8445d2d859414741e11bd49bce5da459675096f6e5e62",
            "1da8a81df753aba23aeecb30f5c8c1fd3384479345b707f904cc7100e8a69b97",
            "ed08b4b60a9b6f4836c4b4ac90979a6084ba416e618fa146f2ca0d6cdb9da8c5",
            "2728c7957bb369dfff36d8619b4b0c5f3e7c9b22552719abee1bcbf2208c425e",
            "ca71d5f1edb0fd3f73d69823881dcba03767969fb889fba34ee4bc102d182627",
            "9879eb3a0248a62047b22c2a735ed2d937ee5127d5936931dfc41a572468229f",
            "03f78bbfeda3d9916f140a94e9c129c09e2bea377629e96e2838e91d04d4817c53d63dc4fc1e3ae5919f762bfcbd1b62437c6ee0d6f3b2e025d945bd82ce00b2",
        ]
    );
    eprintln!(
        "core_gold_data_original_regression capture_only=false golden_set=true H={} MAIN={} PP={} PV={} BASE={} EXT={} original={} packed={} degree={} chunks={} symbolic_bytes={} ordered={} full_pp={} public_values={} math_profile={} wire_profile={} request_sha256={} binding={} MAIN_allocated=false PP_matrix_allocated=false PP_commitment=false proof=false admission=false",
        HEIGHT,
        WIDTH,
        PP_WIDTH,
        air.num_public_values(),
        counts[0],
        counts[1],
        counts[2],
        counts[3],
        degree,
        1usize << (log + zk),
        symbolic_bytes,
        actual[0],
        actual[1],
        actual[2],
        actual[3],
        actual[4],
        actual[5],
        actual[6]
    );
}
