//! Explicit public test inputs; random SDK key bytes stay guarded and are never printed.
use super::witness::{hash_fields, pack_secret};
use super::*;
use fhe::bfv::{BfvParameters, BfvParametersBuilder, Ciphertext, Encoding, Plaintext, SecretKey};
use fhe_traits::{FheEncoder, FheEncrypter, Serialize};
use p3_field::PrimeCharacteristicRing;
use std::sync::{Arc, OnceLock};
use zeroize::Zeroizing;

pub(super) fn fixture() -> (Expected, Prepared) {
    static PARAMETERS: OnceLock<Arc<BfvParameters>> = OnceLock::new();
    let parameters = PARAMETERS.get_or_init(|| {
        BfvParametersBuilder::new()
            .set_degree(N)
            .set_plaintext_modulus(T)
            .set_moduli(&Q)
            .set_variance(10)
            .build_arc()
            .unwrap()
    });
    let key = SecretKey::random(parameters, &mut rand::rng());
    let mut source = Zeroizing::new(vec![0u64; N]);
    let mut mask = Zeroizing::new(vec![0u64; N]);
    for (i, (age, amount)) in [(0usize, 65535u64), (1, 0), (128, 255), (255, 65534)]
        .into_iter()
        .enumerate()
    {
        source[2 * i * 512 + age] = 256 + age as u64;
        source[(2 * i + 1) * 512 + age] = amount;
    }
    for age in 128..256 {
        mask[255 - age] = 1;
    }
    let mut ciphertexts = Vec::with_capacity(2);
    for raw in [&source, &mask] {
        let plaintext = Zeroizing::new(
            Plaintext::try_encode(raw.as_slice(), Encoding::poly(), parameters).unwrap(),
        );
        let ct: Ciphertext = key.try_encrypt(&*plaintext, &mut rand::rng()).unwrap();
        ciphertexts.push(
            Ciphertext::new(ct.iter().cloned().collect(), parameters)
                .unwrap()
                .to_bytes(),
        );
    }
    let request = Request::checked([0x61; 32], ciphertexts.try_into().unwrap()).unwrap();
    let contexts =
        core::array::from_fn(|role| core::array::from_fn(|i| Val::from_usize(101 + role * 16 + i)));
    let salts: [[u64; 4]; 3] = [[7, 8, 9, 10], [11, 12, 13, 14], [15, 16, 17, 18]];
    let words = [
        Zeroizing::new(source.iter().map(|&v| v * SCALE % T).collect::<Vec<_>>()),
        Zeroizing::new(mask.iter().map(|&v| v * SCALE % T).collect::<Vec<_>>()),
    ];
    let key_bytes = Zeroizing::new(key.to_bytes());
    let secret = Zeroizing::new(fhe::proto::bfv::SecretKey::from(&key).coeffs);
    let packed = pack_secret(&secret).unwrap();
    let roots = [
        hash_fields(contexts[0], &salts[0], &words[0]).unwrap(),
        hash_fields(contexts[1], &salts[1], &words[1]).unwrap(),
        hash_fields(contexts[2], &salts[2], &packed).unwrap(),
    ];
    let expected = Expected::checked(request, [0x71; 64], contexts, roots).unwrap();
    let [source, mask] = words;
    let prepared = Prepared::new(
        &expected,
        [
            ScaledOpening::checked(contexts[0], roots[0], source, Zeroizing::new(salts[0]))
                .unwrap(),
            ScaledOpening::checked(contexts[1], roots[1], mask, Zeroizing::new(salts[1])).unwrap(),
        ],
        SecretOpening::checked(contexts[2], roots[2], key_bytes, Zeroizing::new(salts[2])).unwrap(),
    )
    .unwrap();
    (expected, prepared)
}

#[test]
fn canonical_request_and_foreign_prepared_reject_before_main() {
    let (expected, prepared) = fixture();
    assert_eq!(
        Request::decode(expected.request().bytes()).unwrap().bytes(),
        expected.request().bytes()
    );
    let mut appended = expected.request().bytes().to_vec();
    appended.push(0);
    assert!(Request::decode(&appended).is_err());
    let mut foreign = expected.request().bytes().to_vec();
    foreign[8] ^= 1;
    assert!(matches!(Request::decode(&foreign), Err(Error::Encoding)));
    let mut nonce = expected.request().nonce();
    nonce[0] ^= 1;
    let bytes = expected.request().bytes();
    let a = u32::from_le_bytes(bytes[72..76].try_into().unwrap()) as usize;
    let changed = Request::checked(
        nonce,
        [bytes[80..80 + a].to_vec(), bytes[80 + a..].to_vec()],
    )
    .unwrap();
    assert_ne!(changed.q(), expected.request().q());
    let foreign =
        Expected::checked(changed, [0x71; 64], expected.contexts(), expected.roots()).unwrap();
    assert!(matches!(
        prepared.require_expected(&foreign),
        Err(Error::Binding)
    ));
    assert!(matches!(
        Request::checked([0; 32], [vec![], vec![]]),
        Err(Error::Binding)
    ));
}

#[test]
fn openings_reject_wrong_full_word_tail_salt_secret_and_bounds() {
    let context = [Val::ONE; 8];
    let salt = [1u64; 4];
    let words = Zeroizing::new(vec![0u64; N]);
    let root = hash_fields(context, &salt, &words).unwrap();
    let mut changed = words.clone();
    changed[N - 1] = 1;
    assert!(matches!(
        ScaledOpening::checked(context, root, changed, Zeroizing::new(salt)),
        Err(Error::Binding)
    ));
    let mut invalid = words.clone();
    invalid[N - 1] = T;
    assert!(matches!(
        ScaledOpening::checked(context, root, invalid, Zeroizing::new(salt)),
        Err(Error::Shape)
    ));
    assert!(matches!(
        ScaledOpening::checked(context, root, words, Zeroizing::new([2; 4])),
        Err(Error::Binding)
    ));
    let mut secret = Zeroizing::new(vec![0u8; N + 3]);
    secret[..3].copy_from_slice(&[0x0a, 0x80, 0x20]);
    let packed = pack_secret(&vec![0; N]).unwrap();
    let root = hash_fields(context, &salt, &packed).unwrap();
    let mut bad = secret.clone();
    bad[N + 2] = 42;
    assert!(matches!(
        SecretOpening::checked(context, root, bad, Zeroizing::new(salt)),
        Err(Error::Arithmetic)
    ));
    secret[N + 2] = 2;
    assert!(matches!(
        SecretOpening::checked(context, root, secret, Zeroizing::new(salt)),
        Err(Error::Binding)
    ));
}

#[test]
fn graph_fft_matches_independent_full_negacyclic_integer_oracle() {
    let fft = fft::Plan::new().unwrap();
    let a = (0..N)
        .map(|i| (i as u64 * 7919 + Q[0] - 2) % Q[0])
        .collect::<Vec<_>>();
    let s = Zeroizing::new((0..N).map(|i| (i % 41) as i64 - 20).collect::<Vec<_>>());
    let frequency = fft.secret_frequency(&s).unwrap();
    let actual = fft.product(&a, &frequency, Q[0]).unwrap();
    let mut expected = Zeroizing::new(vec![0i128; N]);
    for (i, &x) in a.iter().enumerate() {
        for (j, &y) in s.iter().enumerate() {
            let term = i128::from(x) * i128::from(y);
            if i + j < N {
                expected[i + j] += term
            } else {
                expected[i + j - N] -= term
            }
        }
    }
    for (a, e) in actual.iter().zip(expected.iter()) {
        assert_eq!(i128::from(*a), *e);
    }
}

// PUBLIC metadata-only Pair snapshot. These literal coefficients are deliberately
// not claimed to be an encryption, a private witness, or an accepted query.
fn pair_snapshot_varint(mut value: usize, output: &mut Vec<u8>) {
    while value >= 128 {
        output.push((value as u8 & 127) | 128);
        value >>= 7;
    }
    output.push(value as u8);
}
pub(super) fn pair_snapshot_ciphertext(operand: usize) -> Vec<u8> {
    let mut ciphertext = Vec::new();
    for component in 0..2 {
        let mut packed = Vec::with_capacity(N * 60 / 8);
        for (basis, &modulus) in Q.iter().enumerate() {
            let mut pending = 0u64;
            let mut bits = 0;
            for index in 0..N {
                let value = if index == N - 1 || index % 257 == 0 {
                    modulus - 1
                } else if index % 257 == 1 {
                    0
                } else {
                    (index as u64 * 2_654_435_761
                        + operand as u64 * 104_729
                        + component as u64 * 7_919
                        + basis as u64 * 65_537)
                        % modulus
                };
                pending |= value << bits;
                bits += 30;
                while bits >= 8 {
                    packed.push(pending as u8);
                    pending >>= 8;
                    bits -= 8;
                }
            }
            assert_eq!(bits, 0);
            assert_eq!(pending, 0);
        }
        assert_eq!(packed.len(), N * 60 / 8);
        let mut polynomial = vec![8, 2, 16];
        pair_snapshot_varint(N, &mut polynomial);
        polynomial.push(26);
        pair_snapshot_varint(packed.len(), &mut polynomial);
        polynomial.extend(packed);
        ciphertext.push(10);
        pair_snapshot_varint(polynomial.len(), &mut ciphertext);
        ciphertext.extend(polynomial);
    }
    ciphertext
}
fn pair_snapshot_expected() -> Expected {
    let request = Request::checked(
        [0x93; 32],
        [pair_snapshot_ciphertext(0), pair_snapshot_ciphertext(1)],
    )
    .unwrap();
    assert_eq!(
        Request::decode(request.bytes()).unwrap().bytes(),
        request.bytes()
    );
    let contexts = core::array::from_fn(|role| {
        core::array::from_fn(|word| Val::from_usize(1_001 + role * 97 + word * 17))
    });
    let roots = core::array::from_fn(|role| {
        core::array::from_fn(|word| Val::from_usize(2_003 + role * 193 + word * 31))
    });
    Expected::checked(request, [0xa7; 64], contexts, roots).unwrap()
}

// Stream the actual native serde representation: SymbolicExpr uses upstream's
// deterministic post-order FlatNode enum. Pointer addresses are never serialized.
// The bound limits the stream, without retaining a second serialized AST buffer.
struct PairSnapshotHash {
    hash: sha2::Sha256,
    bytes: usize,
}
impl PairSnapshotHash {
    fn new() -> Self {
        use sha2::Digest;
        let mut hash = sha2::Sha256::new();
        hash.update(b"DCS/CoreGold/Pair-ordered-symbolic/postcard-p3-0.8/v1");
        Self { hash, bytes: 0 }
    }
}
impl postcard::ser_flavors::Flavor for PairSnapshotHash {
    type Output = ([u8; 32], usize);
    fn try_push(&mut self, value: u8) -> postcard::Result<()> {
        self.try_extend(&[value])
    }
    fn try_extend(&mut self, bytes: &[u8]) -> postcard::Result<()> {
        use sha2::Digest;
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .filter(|&size| size <= 64 * 1024 * 1024)
            .ok_or(postcard::Error::SerializeBufferFull)?;
        self.hash.update(bytes);
        Ok(())
    }
    fn finalize(self) -> postcard::Result<Self::Output> {
        use sha2::Digest;
        Ok((self.hash.finalize().into(), self.bytes))
    }
}
fn pair_snapshot_hex(bytes: [u8; 32]) -> String {
    use std::fmt::Write;
    let mut output = String::with_capacity(64);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").unwrap();
    }
    output
}

#[test]
fn ordered_pair_constraints_lookups_and_full_preprocessing_snapshot() {
    use bfv_hiding_stark::{Challenge, Challenger, Pcs};
    use p3_air::{BaseAir, symbolic::AirLayout};
    use p3_batch_stark::symbolic::{
        get_log_num_quotient_chunks_for_domain, get_symbolic_constraints,
    };
    use p3_commit::{PolynomialSpace, UnivariateStarkPcs};
    use p3_field::{PrimeField64, coset::TwoAdicMultiplicativeCoset};
    use p3_lookup::{LogUpGadget, Lookups};
    use p3_matrix::Matrix;
    use sha2::Digest;

    // Native Pair digests captured before single-DATA dispatch: mathematical
    // profile, wire profile, every ordered symbolic constraint and every PP cell.
    const GOLDEN: [&str; 4] = [
        "1d46aabee8b12e654743ca89bd9f8e22f6eca41eba415d0a4de860790f6ffa09",
        "b4026496eec3f20a214ebe6f5a1ce2de4a7ae5a6394977c5c69c548cd8601d4b",
        "be34a0d28c815be2e06e2ed8a7e8cdc9df5c443d3a66832525f6c4b7ee83ddd3",
        "2734dbd8f156b96508c4db6269586f03294502f6ed8ac986723bc8846dbc0a07",
    ];
    let air = program::ProgramAir::new(pair_snapshot_expected()).unwrap();
    assert_eq!(air.width(), 512);
    assert_eq!(air.preprocessed_width(), 272);
    assert_eq!(air.num_public_values(), 36);
    let (symbolic_hash, symbolic_bytes, counts) = {
        let layout = AirLayout::from_air(&air);
        let domain = TwoAdicMultiplicativeCoset::<Val>::new(Val::ONE, 13).unwrap();
        let zk = usize::from(<Pcs as UnivariateStarkPcs<Challenge, Challenger>>::ZK);
        assert_eq!(zk, 1);
        let gadget = LogUpGadget::new();
        let original = Lookups::<Val>::from_air::<Challenge, _>(&air);
        let log = get_log_num_quotient_chunks_for_domain::<Val, Challenge, _, _>(
            &air, layout, domain, &original, zk, &gadget,
        );
        let budget = (1usize << log) + 1 - zk;
        let packed = original
            .clone()
            .pack_same_bus_with_degree(budget, |lookup| {
                gadget
                    .constraint_degree_with_transition(lookup, domain.transition_degree_multiple())
            });
        assert_eq!(
            get_log_num_quotient_chunks_for_domain::<Val, Challenge, _, _>(
                &air, layout, domain, &packed, zk, &gadget,
            ),
            log
        );
        let (base, extension) =
            get_symbolic_constraints::<Val, Challenge, _, _>(&air, layout, &packed, &gadget);
        let counts = [base.len(), extension.len(), original.len(), packed.len()];
        assert_eq!(counts, [1_588, 46, 128, 43]);
        let (hash, bytes) = postcard::serialize_with_flavor(
            &(base, extension, original, packed),
            PairSnapshotHash::new(),
        )
        .unwrap();
        (hash, bytes, counts)
    }; // Drop symbolic DAGs before allocating the complete public PP matrix.
    let pp = air.preprocessed_trace().expect("fixed actual Pair PP");
    assert_eq!((pp.height(), pp.width()), (8_192, 272));
    assert_eq!(pp.values.len(), 8_192 * 272);
    let mut pp_hash = sha2::Sha256::new();
    pp_hash.update(b"DCS/CoreGold/Pair-full-preprocessing/LE64/v1");
    for dimension in [pp.height(), pp.width()] {
        pp_hash.update((dimension as u64).to_le_bytes());
    }
    for value in &pp.values {
        pp_hash.update(value.as_canonical_u64().to_le_bytes());
    }
    let actual = [
        pair_snapshot_hex(profile_digest()),
        pair_snapshot_hex(wire::profile()),
        pair_snapshot_hex(symbolic_hash),
        pair_snapshot_hex(pp_hash.finalize().into()),
    ];
    eprintln!(
        "core_gold_pair_snapshot golden_set=true base={} extension={} original_lookups={} packed_lookups={} symbolic_bytes={} pp_fields={} pp_bytes={} math_profile={} wire_profile={} ordered_symbolic={} full_pp={}",
        counts[0],
        counts[1],
        counts[2],
        counts[3],
        symbolic_bytes,
        pp.values.len(),
        pp.values.len() * 8,
        actual[0],
        actual[1],
        actual[2],
        actual[3]
    );
    for (actual, expected) in actual.iter().zip(GOLDEN) {
        assert_eq!(
            actual, expected,
            "CoreGold Pair byte-contract golden changed"
        );
    }
}
