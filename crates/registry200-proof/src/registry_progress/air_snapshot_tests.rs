//! PUBLIC NONSECRET metadata snapshots, never Source/Encoding proof admission.
//! Both old roles retain their exact native ordered equations and public schedule.
use super::{transition, transition_air::ProgressAir, transition_layout::TRACE_WIDTH};
use crate::{
    Val,
    admission::CanonicalSource,
    coefficient_encoding::{
        self as encoding,
        statement::{BfvBinding, Expected as QueryExpected, Statement as QueryStatement},
    },
    source,
};
use bfv_hiding_stark::{Challenge, TRACE_HEIGHT};
use p3_air::{
    BaseAir,
    symbolic::{AirLayout, get_all_symbolic_constraints},
};
use p3_field::PrimeCharacteristicRing;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

// [complete data image, complete index image, q, Ckey, Copen], lowercase hex.
// Captured once from the published PUBLIC0x71 test authority; no proof admission.
const PUBLIC_SOURCE: [&str; 5] = [
    "4353544f5245303142424242424242424242424242424242737373737373737373737373737373734351414745414d4f554e54303030303100000000000000000300000000010000040000000000000021ec2d15223a6eb37a768380975850b93bb1fa79424297c136bfaa041ad5b82500000000000000000d5c84754de64d5eca6946c8ab94177cc6e9a1bb2e1c05b2e4760d19ff9aebf934e048fc9db372a739166a86a99cbab7c61203d3",
    "4353544f5245303142424242424242424242424242424242737373737373737373737373737373734351414745494e4445583030303030330000000000000000010000000010000020090000000000006844d5608f5b28e2724499a66ada8e5b754e122dc07d99c67d6ca868b43cf8340000000000000000b8c836aa46d3dd06fa69286b3d26c6b5c9dc5a123477d5a9c97da7df9ee1a64bcc10b25c6e2935f804495e37a62d63edd4f32e56e2a56f874a0eeae2c4bb371edd898c8522ac0f5fd7db8717a3396dac5eecab4e71ac11cd60c8edc9115131cccf9de132f00451ca8047db66d2ce3590319d32db43377cc118011fa63584e011fffd6a1af86530dc0648292440bf3b9583de88bdd31d0b64c56ceb041f2b7d1931e09287c5c8b85dda452ee48ac5e25e0e3b07f13b1612670e81ccf31fb701e27bdfb6ba2d4e9b2a487052b9df0553c4a3119760a1555cfd028933686f8b3d4d2ddbf49027aa2e3357982d58ca50136c96a24e558c41048b2e5d6bb5b5cbdf29cff5d264312a1fe138562c1fbe58bc69230222ac8d530738836d03a16451f2d2f1a19c8d51a86788afab475009108dc3bcfdd0d7f47dcdf8f7c2e47b563074ff2b1f8b8a522baa91d93433b60871149d724d9e738f9a66cf959c7225c3e13cb4f15cc739bc2df53e44c6f7a2b346736f26357480dcff58d9359b3f8ed92108295b13b4371ac83ab3589622a0c5d5d5144ee31a8a8d717452e4c9db79ca07af77476a19bab9696c8a39d7be14e818105e41389129c227fbc2ebccd3ad4f490bf94df293fe5f913e1595ad75f240d58c9a03adfce8871a6afbf457882940546bfe8e3a80e6965eaa188a63a429cc9d64edd18a20fcef44448f08292e6bb911fe0ab33568d442106943e017a957b3edc58b8c585583d444dab44b08d80369053aa39a8cdd69a430fe20332504ce47379b30c83ae05bcb5c7a5b873e827aebdcf872139f7ac794db38694c231126fb856c2619a5f413455df4abf12d3198ae7893e13b9233c334f6f347686a2b7e77c0174efd74a2493c436ec96aeb67be0cf0a5b475168da2d9e5a4b042233ac80d8422c522059c33ef27cefc5c218e4c97dc07d5f0c91b20886dc9c08a3373e058fb039c69d2a38e7580ebc09678e82b643b135243b637369cf041253fca12b7909a1a138df1f69267f53d1ffdf30258398eef214d6fbeafb1daa585f020fec6e398175e936b50bf9843d512bd0f82b76515aab736e764642aec73062e7f99f5445625e3ad78c446430d751eab1dea9ff42c03f671c65f25e66a188717800db3dfbcbb98c5e3f038e4b006294386d5ee4acf4812330b4de5ed0067837cb09c1ce9190eec008c0105350440cc71569d3c878f104b9f562663b939e82ee1b2163c77c3c4efee303fdd2be7ff45199a31558cfd1e8c646bbd536d5d18ba8d1728a015399b6530eaa1b5efb65ceb6cc102ad7e0c9e71611961a0d35761cb7330a97622e3747af7e72b7940330421e30e8388258ff50b84afb539e6eb61a20b111461b0bbf00a8b866e970538cba1d153598e4538ce162b46c5bde0753790d7ceae4c7a15f800bcbd01b8da6235a81b3a4bbe280c930c1efda64b43da63829af3cff7755a61a2120902550dcd81816dc6f907be15e8878a8d04371f6c91e2c75b903c8be5b380e74f8f5ea5b16b85a633821b9aac05242812627dfc1b3d1439f83f5369fd3b0bf469e8d45b330819c09ee863b0b97aa76b982a1dcb4625aaa6a95ee40fe3a9ab4a06ac264cebad6b6963f198b11b01ccef75915b7b671f5e9aa3453f5bcd8036f87202d176d58a8132879de0a8735b7f3b710b69e54c645f21d85725808b6e4bbc212e8dae3480a62b1e87f577db8110a882dbf4cca045dcc3304540020a314afb39e4511015d4721f2e908358b2dbad9eb1543e6b4bb4216570e530932be3440450b9fe3d158475a4cc8e13507c282297bcf481a659f01207e4674df0ea904864b6b27be3e49172895f595ca3b290895052f40797640445b75f3a5d4da4a81d2fbf6463ad2d30959c7d162b1ebad6dbca87b00745654dc12603263221b720b89f9045293e2bd1c57e21a968a4c1ac73b6e9ec3c30eace6b9f079fa8a8f4131e3c5f962c5a1926c6ced73315f1cc111c91989467ad4d99091dcf9bf8984cfe643d92cc34143c607ec04c167339e10f81e6ca833b35fb99e979ccd35066a843db82c7f031c6b376677b9c017d332bd985f49da82e8b17739162c6da95b43ad8500252fc1a5ba0602122ce4a3a70f4176121ca7ec4131cf38b6cf131c9015a9d55512ed9693602e377811c09b37e9e60f1e3732be6fb18d015ef29cc1be8337d874451d840e1e8516adeb58df65dc78b1d3492174eb75d8bdbb0192a7d4f9761de083450bba9f29cac44234c4195d4ba644986c26172a2a1ac8b1e816b26c50a041b114a8013bb778fce4c6ade2199da78d13e217de87f9f526709d4171e4eaddd5268a949982b2ed1ccee3a59da6b262f3619af7f901f6c44fbb896ee34399ec93cefb544aa4ea07927eb299a968d0c40a46c4df3c1f99b3daa768d6259100b15a0e63093885bd1d24f9e10ac3e6e4ff237cc69c168e3c91aadcaa00a251b9af975f16f02e36417277ca2d637b70b5f6d9772fcf72930c8bcf97455500f773d180c82ee8a2a4330e1def5ae076d1fe11e6fd637c1db2ce0d5cf71ff92ec1375d9bb5a05e6700bf4d55087bc2464750d0f658dc4bbef2a829c6574d2b1c99ac13c7f1123bf92e5effb6fcc7a3fcada19ee4d21650dc639e0df8118c8a0a9257a83cc03f14067a9adab4973da88cbc762056feaa4a268164f56e74054aa941dc157e82696f09264477727be451b115c5d6bb59758db5b39388b9fb6ae9d4d20ff50104cbd3f00c2a23a744c1a8ba420ba8e2cc386963aae7063cb93ba8d921458e4c27f313e42d12fcdb1fd14f23875faf70415950dce7167ba206701a5a51e34990d29b1a27bc8c27ff8e3ccc78a02c0d8653a96456a467a6284f224acb3ef46b1d891fabaa29d2d193a28e426e0ec34da5c839c06fcdf2497bc21af44699856e284f6041bf161fcf7857bc2a51a35d5d092da29879fffd28505335abecf3d9f565466a03390c093de3f13f79ca1e7b2524055851a7b5a6c75eb27390b9ad0f72236712c5bf327b8476dd2fb421f89f47e307ad805bfe54d0d0b7e6d3d962dc257d14097bebdcbcf405d5f421549eae25a501658c76cc53ff4bb4ad714d0f4ef30b89fe67dc66384ce8d28865bfbf7737d931c84de62bfea2ccbd9c53c0e9ae2e835f4a43ff9599bdb6f839e8232bb7399273063ccc8f4b1b32063479db64d0bcf9678c0b5a55624d864a1e33c3fc0fb4acef9c316e5e4bc2d51072923b3dd12f8be087e55f8dac1951b4e921dade68a10791bdd5d0d4a29df4845f446ab68853b4f85262959057d303d89ef2720659f98c3c170fc795b902ebc1d87b2fddd89c39fcbf82ff0f821407c9623fe66f58cfb112abd1fcee46492",
    "8383838383838383838383838383838383838383838383838383838383838383",
    "8ecade11d34f57e651fde8c83392f8692b816e9e8069461eb5d5668ddc21e2ba",
    "e20cf6bc9cbdcb5c6077644a3645a8c4a281539e1cbfd3427c7a2b4409c24ab7",
];
// Per role: transition profile (also the detached wire profile), complete public
// statement, ordered BASE/EXT+BaseAir metadata, every periodic column cell.
const CONTROL_GOLDEN: [&str; 4] = [
    "7b91cf00e1ee5c486242874e1542d6d262b301797b9147b644ce6026501aeaa2",
    "cfd3f509b0ba4aebd3b429d4640ae113c42eed7e015672f7d502e1b5f86a1913",
    "29e2696494652ab2fcad4a81578998b7b38d2a672f9be2c0f572f3cf1dc69a20",
    "fc2ec0542376ae3bef284da4c20651ab3034cd74605d72ed375e713eaf9ead89",
];
const PREDICATE_GOLDEN: [&str; 4] = [
    "5e145e2e14c019e11803e4c5019e58d1143e318395c8cc41490e21172a66ec36",
    "044c6e2eae955dc8a11de129ce9a90dde98e2b55b6d3278bf570ca9c682b6410",
    "6b2d8a042292300d266b8a06d0cd2384a08d724729329bfca03f88bf43aa0ff0",
    "fc2ec0542376ae3bef284da4c20651ab3034cd74605d72ed375e713eaf9ead89",
];

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut text, "{byte:02x}").unwrap();
    }
    text
}
fn unhex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}
fn decode_public_source(fields: [&str; 5]) -> CanonicalSource {
    let data = unhex(fields[0]);
    let index = unhex(fields[1]);
    assert_eq!((data.len(), index.len()), (172, 2496));
    let heads = [
        compact_store::Commitment::decode(&data[..112], source::statement::limits()).unwrap(),
        compact_store::Commitment::decode(&index[..112], source::statement::limits()).unwrap(),
    ];
    let claim = source::Statement::checked_relation(
        source::Relation::CanonicalIndex,
        [&data, &index],
        [&heads[0], &heads[1]],
        unhex(fields[2]).try_into().unwrap(),
        unhex(fields[3]).try_into().unwrap(),
        unhex(fields[4]).try_into().unwrap(),
    )
    .unwrap();
    CanonicalSource::checked_claim(&claim).unwrap()
}
fn public_source() -> &'static CanonicalSource {
    static SOURCE: OnceLock<CanonicalSource> = OnceLock::new();
    SOURCE.get_or_init(|| decode_public_source(PUBLIC_SOURCE))
}
fn digest(value: u32) -> [u8; 32] {
    source::statement::encode_digest([Val::from_u32(value); 4])
}
// A pure metadata factory for this baseline and test-private semantic lowering.
// Literal Key33/Cmask/Cw roots below are public mathematical claims, not proofs.
pub(super) fn statements() -> (transition::Statement, transition::Statement) {
    let source = public_source();
    let control = transition::Expected::control(
        source,
        [0xa7; 32],
        [0xb7; 32],
        digest(3),
        digest(5),
        digest(7),
    )
    .unwrap();
    let key = bfv_key_transform::Statement {
        expected: bfv_key_transform::Expected {
            descriptor: bfv_key_transform::SetupDescriptor {
                database: source.claim().heads[0][8..24].try_into().unwrap(),
                key_domain: [0x71; 16],
                public_setup_digest: [0x95; 32],
                key_epoch: 1,
            },
            coefficients: [Val::from_u32(11); 4],
        },
        transformed: [Val::from_u32(12); 4],
    };
    let query = QueryStatement {
        expected: QueryExpected::private_mask(
            source,
            BfvBinding::new([0x53; 32], key),
            [0x61; 32],
            [0x62; 32],
            digest(13),
        )
        .unwrap(),
        encoded: [Val::from_u32(17); 4],
    };
    assert_eq!(query.expected.role(), encoding::Role::PrivateMask);
    let predicate = transition::Expected::predicate(
        &query,
        [0xa7; 32],
        [0xb7; 32],
        digest(3),
        digest(5),
        digest(7),
    )
    .unwrap();
    (
        transition::Statement::from_claim(&control, digest(19), digest(23)).unwrap(),
        transition::Statement::from_claim(&predicate, digest(29), digest(31)).unwrap(),
    )
}

// Native serde walks upstream SymbolicExpr's ordered FlatNodes. Stream directly
// into SHA256 so the snapshot does not retain a second serialized DAG buffer.
struct SnapshotHash {
    hash: Sha256,
    bytes: usize,
}
impl SnapshotHash {
    fn new(domain: &[u8]) -> Self {
        let mut hash = Sha256::new();
        hash.update(b"DCS/ProgressAir/native-postcard-p3-0.8/v1");
        hash.update((domain.len() as u64).to_le_bytes());
        hash.update(domain);
        Self { hash, bytes: 0 }
    }
}
impl postcard::ser_flavors::Flavor for SnapshotHash {
    type Output = ([u8; 32], usize);
    fn try_push(&mut self, value: u8) -> postcard::Result<()> {
        self.try_extend(&[value])
    }
    fn try_extend(&mut self, bytes: &[u8]) -> postcard::Result<()> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .filter(|&n| n <= 64 * 1024 * 1024)
            .ok_or(postcard::Error::SerializeBufferFull)?;
        self.hash.update(bytes);
        Ok(())
    }
    fn finalize(self) -> postcard::Result<Self::Output> {
        Ok((self.hash.finalize().into(), self.bytes))
    }
}
fn snapshot(statement: &transition::Statement, golden: [&str; 4]) {
    let predicate = statement.expected().is_predicate();
    let air = ProgressAir::new(statement);
    let layout = AirLayout::from_air(&air);
    assert_eq!(air.width(), TRACE_WIDTH);
    assert_eq!(air.width(), 8266);
    assert_eq!(air.num_public_values(), if predicate { 896 } else { 815 });
    assert_eq!(air.preprocessed_width(), 0);
    assert_eq!(air.num_periodic_columns(), TRACE_HEIGHT);
    assert_eq!(
        air.main_next_row_columns(),
        (0..TRACE_WIDTH).collect::<Vec<_>>()
    );
    assert!(air.preprocessed_next_row_columns().is_empty());
    assert!(air.public_boundary_io().is_empty());
    assert!(!air.assumes_boolean_trace());
    let values = statement.values();
    let (public_hash, public_bytes) = postcard::serialize_with_flavor(
        &(statement.identity().as_slice(), &values),
        SnapshotHash::new(b"full-statement"),
    )
    .unwrap();
    let (symbolic_hash, symbolic_bytes, counts) = {
        let (base, extension) = get_all_symbolic_constraints::<Val, Challenge, _>(&air, layout);
        let counts = [base.len(), extension.len()];
        let metadata = (
            layout,
            air.main_next_row_columns(),
            air.preprocessed_next_row_columns(),
            air.num_constraints(),
            air.max_constraint_degree(),
            air.public_boundary_io(),
            air.assumes_boolean_trace(),
            &values,
        );
        let (hash, bytes) = postcard::serialize_with_flavor(
            &(metadata, base, extension),
            SnapshotHash::new(b"ordered-symbolic-and-metadata"),
        )
        .unwrap();
        (hash, bytes, counts)
    }; // Drop actual symbolic DAGs before visiting the complete periodic table.
    let periodic = air.periodic_columns();
    assert_eq!(periodic.len(), TRACE_HEIGHT);
    assert!(periodic.iter().all(|column| column.len() == TRACE_HEIGHT));
    let (periodic_hash, periodic_bytes) = postcard::serialize_with_flavor(
        periodic.as_ref(),
        SnapshotHash::new(b"full-periodic-columns"),
    )
    .unwrap();
    let actual = [
        hex(&transition::profile_digest(predicate)),
        hex(&public_hash),
        hex(&symbolic_hash),
        hex(&periodic_hash),
    ];
    eprintln!(
        "progress_air_snapshot role={} golden_set=true width={} height={} pv={} base={} extension={} public_bytes={} symbolic_bytes={} periodic_columns={} periodic_fields={} periodic_bytes={} math_and_wire_profile={} full_statement={} ordered_symbolic={} full_periodic={}",
        if predicate {
            "predicate896"
        } else {
            "control815"
        },
        air.width(),
        TRACE_HEIGHT,
        values.len(),
        counts[0],
        counts[1],
        public_bytes,
        symbolic_bytes,
        periodic.len(),
        periodic.iter().map(Vec::len).sum::<usize>(),
        periodic_bytes,
        actual[0],
        actual[1],
        actual[2],
        actual[3],
    );
    for (actual, expected) in actual.iter().zip(golden) {
        assert_eq!(
            actual, expected,
            "old ProgressAir ordered/periodic/profile contract changed"
        );
    }
}
#[test]
fn ordered_control815_constraints_periodics_and_profiles_snapshot() {
    snapshot(&statements().0, CONTROL_GOLDEN);
}
#[test]
fn ordered_predicate896_constraints_periodics_and_profiles_snapshot() {
    snapshot(&statements().1, PREDICATE_GOLDEN);
}
