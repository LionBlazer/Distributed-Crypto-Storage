//! Independent public metadata only; actual verify_pair remains mandatory before proving.
use super::*;
use crate::gold_formation::{Inputs, graph};
use crate::statement::Statement;
use bfv_hiding_stark::Val;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use registry200_proof::two_lane_encoding::{
    Role, statement::Statement as Encoded, wire::VerifiedPair,
};
use sha2::{Digest, Sha256, Sha512};
use std::sync::Arc;

pub(super) struct Descriptor {
    pub(super) graph: graph::Plan,
    pub(super) c0: [Vec<u64>; 4],
    pub(super) contexts: [[Val; 8]; 3],
    pub(super) roots: [[Val; 4]; 3],
    pub(super) values: Vec<Val>,
    // None is a geometry-only planning input, structurally ineligible for the pair fence.
    claims: Option<[Encoded; 2]>,
}
impl Descriptor {
    /// This constructs an UNVERIFIED AIR expectation. It is not a pair/key proof.
    pub(super) fn from_claims(
        original: &Statement,
        source: Encoded,
        mask: Encoded,
    ) -> Result<Self> {
        let se = &source.expected;
        let me = &mask.expected;
        if se.role() != Role::SourceAllOriginal
            || me.role() != Role::PrivateMask
            || se.source_claim().values() != me.source_claim().values()
            || se.source_claim().heads != me.source_claim().heads
            || se.source_claim().packets != me.source_claim().packets
            || se.key_binding().values() != me.key_binding().values()
            || me.public_nonce() != original.binding()
        {
            return Err(Error::Binding);
        }
        se.source_claim().reaudit().map_err(|_| Error::Binding)?;
        me.source_claim().reaudit().map_err(|_| Error::Binding)?;
        // Explicit NEW experiment contract; incompatible with q(parent). No cyclic q in request.
        let mut q = Sha256::new();
        q.update(b"DCS/GOLD-FORMATION/exact-input-request-q/v1");
        q.update((original.request_wire().len() as u64).to_le_bytes());
        q.update(original.request_wire());
        if se.source_claim().request != <[u8; 32]>::from(q.finalize()) {
            return Err(Error::Binding);
        }
        let key = se.key_binding().values();
        if key.len() != 29 {
            return Err(Error::Shape);
        }
        // Closed exact KeyBinding grammar: database4/domain4/epoch1/param8/keyID8/Cs4.
        // Its first25 fields form the Cs scope; NEVER hash Cs into its own context.
        let mut cs = Sha256::new();
        cs.update(b"DCS/GOLD-FORMATION/Cs528/N4096/packed-six-bit/v1");
        cs.update(profile());
        for v in &key[..25] {
            cs.update(v.as_canonical_u64().to_le_bytes());
        }
        let cs_context = words(&<[u8; 32]>::from(cs.finalize()));
        let contexts = [se.encoding_context(), me.encoding_context(), cs_context];
        let roots = [
            source.encoded,
            mask.encoded,
            key[25..29].try_into().map_err(|_| Error::Shape)?,
        ];
        let mut identity = Sha512::new();
        identity.update(b"DCS/GOLD-FORMATION/full-Expected/v1");
        identity.update(profile());
        identity.update((original.request_wire().len() as u64).to_le_bytes());
        identity.update(original.request_wire());
        for s in [&source, &mask] {
            for v in s.values() {
                identity.update(v.as_canonical_u64().to_le_bytes());
            }
            for bytes in s
                .expected
                .source_claim()
                .heads
                .iter()
                .map(|x| x.as_slice())
                .chain(s.expected.source_claim().packets.iter().map(Vec::as_slice))
            {
                identity.update((bytes.len() as u64).to_le_bytes());
                identity.update(bytes);
            }
        }
        let digest: [u8; 64] = identity.finalize().into();
        let mut values = words(&profile()).to_vec();
        values.extend(
            digest
                .as_chunks::<4>()
                .0
                .iter()
                .map(|v| Val::from_u32(u32::from_le_bytes(*v))),
        );
        for root in [roots[2], roots[0], roots[1]] {
            values.extend(root);
        }
        if values.len() != PUBLIC_VALUES {
            return Err(Error::Shape);
        }
        Ok(Self {
            graph: graph::Plan::new(Inputs::new(original)?)?,
            c0: core::array::from_fn(|job| original.input(2 * (job / 2))[job % 2].clone()),
            contexts,
            roots,
            values,
            claims: Some([source, mask]),
        })
    }
    /// Actual canonical SDK request geometry, with NO Source/Cw/Cs claim.
    /// The domain-separated placeholders only instantiate the public columns for
    /// symbolic inspection. This descriptor can never pass require_pair.
    pub(super) fn unverified_geometry(original: &Statement) -> Result<Self> {
        let mut identity = Sha512::new();
        identity.update(b"DCS/GOLD-FORMATION/UNVERIFIED-GEOMETRY-ONLY/v1");
        identity.update((original.request_wire().len() as u64).to_le_bytes());
        identity.update(original.request_wire());
        let digest: [u8; 64] = identity.finalize().into();
        let mut values = words(&profile()).to_vec();
        values.extend(
            digest
                .as_chunks::<4>()
                .0
                .iter()
                .map(|v| Val::from_u32(u32::from_le_bytes(*v))),
        );
        values.extend([Val::ZERO; 12]);
        if values.len() != PUBLIC_VALUES {
            return Err(Error::Shape);
        }
        Ok(Self {
            graph: graph::Plan::new(Inputs::new(original)?)?,
            c0: core::array::from_fn(|job| original.input(2 * (job / 2))[job % 2].clone()),
            contexts: [[Val::ZERO; 8]; 3],
            roots: [[Val::ZERO; 4]; 3],
            values,
            claims: None,
        })
    }
    /// The future concrete consumer must call fresh verify_pair itself and then
    /// this complete association; no caller-supplied boolean substitutes for it.
    pub(super) fn require_pair(&self, pair: &VerifiedPair) -> Result<()> {
        let claims = self.bound_claims()?;
        for (expected, actual) in [
            (&claims[0], pair.source().statement()),
            (&claims[1], pair.private_mask().statement()),
        ] {
            actual
                .require_expected(&expected.expected)
                .map_err(|_| Error::Binding)?;
            if actual.values() != expected.values()
                || actual.expected.source_claim().heads != expected.expected.source_claim().heads
                || actual.expected.source_claim().packets
                    != expected.expected.source_claim().packets
            {
                return Err(Error::Binding);
            }
        }
        Ok(())
    }
    fn bound_claims(&self) -> Result<&[Encoded; 2]> {
        self.claims.as_ref().ok_or(Error::Binding)
    }
    pub(super) fn shared(self) -> Arc<Self> {
        Arc::new(self)
    }
}
fn words(bytes: &[u8; 32]) -> [Val; 8] {
    core::array::from_fn(|i| {
        Val::from_u32(u32::from_le_bytes(
            bytes[4 * i..4 * i + 4].try_into().expect("fixed word"),
        ))
    })
}
pub(super) fn profile() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"DCS/GOLD-FORMATION/FULL-AIR/v1/UNASSESSED/NO-ADMISSION");
    h.update(b"N4096/Q1073692673,1073668097/T65537/D536854528,282551134/W-scaled-once16389;S/E+-20;K+-524287;one-E-per-operand;Cs528-packed6;two-Cw4112;exact-literal-request-q;H8192/MAIN512/PP272/PV36/128ports;sole-terminal0;native0.8-defaultpack;GoldEF5/hiding/Q192/blowup3/salt4/random5/zero-grind");
    h.update(BUS.as_bytes());
    for n in [
        HEIGHT,
        WIDTH,
        PP_WIDTH,
        PUBLIC_VALUES,
        PORTS,
        RANGE_FIRST,
        SOURCE_FIRST,
        MASK_FIRST,
        CS_FIRST,
        PADDING_FIRST,
    ] {
        h.update((n as u64).to_le_bytes());
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geometry::N;
    use crate::gold_formation::program::{air::ProgramAir, assessment, pp};
    use p3_air::BaseAir;
    use std::sync::OnceLock;

    // Only canonical PUBLIC ciphertext bytes survive this one actual SDK setup.
    // Its real random secret and plaintext buffers are dropped inside the fixture.
    fn original() -> &'static Statement {
        static ORIGINAL: OnceLock<Statement> = OnceLock::new();
        ORIGINAL.get_or_init(|| crate::fixture::example().unwrap().statement)
    }
    fn id(value: Val) -> u64 {
        value.as_canonical_u64()
    }

    #[test]
    fn all4096_boundaries_and_actual_graph_fanouts_are_canonical_public_rows() {
        let d = Descriptor::unverified_geometry(original()).unwrap();
        assert!(matches!(d.bound_claims(), Err(Error::Binding)));
        pp::inventory(&d).unwrap();
        let first = pp::row(&d, 0).unwrap();
        assert_eq!(
            [id(first[0]), id(first[1]), id(first[2]), id(first[3])],
            [
                pp::node(0, 0).unwrap(),
                pp::node(0, 2048).unwrap(),
                pp::node(1, 0).unwrap(),
                pp::node(1, 1).unwrap()
            ]
        );
        let twist = crate::gold_formation::fft::pow(crate::gold_formation::fft::PSI, 2048);
        assert_eq!(
            [
                id(first[128]),
                id(first[129]),
                id(first[130]),
                id(first[131])
            ],
            [1, twist, 1, crate::gold_formation::fft::GOLD - twist]
        );
        let final_shared = pp::row(&d, 704).unwrap();
        let shared_flags = core::array::from_fn(|i| id(final_shared[pp::FLAGS + i]) as i32);
        assert_eq!(pp::count(2, &shared_flags), 4);
        assert_eq!(pp::count(3, &shared_flags), 4);
        let point = pp::row(&d, 768).unwrap();
        assert_eq!(
            [id(point[0]), id(point[1]), id(point[2]), id(point[3])],
            [pp::node(12, 0).unwrap(), 0, pp::node(13, 0).unwrap(), 0]
        );
        for index in 0..N {
            let r = pp::row(&d, RANGE_FIRST + index / 2).unwrap();
            let base = 17 * (index % 2);
            assert_eq!(id(r[base]), pp::node(0, index).unwrap());
            for operand in 0..2 {
                assert_eq!(
                    id(r[base + 7 + operand]),
                    pp::node(65 + operand, index).unwrap()
                );
            }
            for job in 0..4 {
                assert_eq!(
                    id(r[base + 9 + job]),
                    pp::node(28 + 12 * job, index).unwrap()
                );
                assert_eq!(
                    id(r[pp::COEFFICIENTS + 4 * (index % 2) + job]),
                    original().input(2 * (job / 2))[job % 2][index]
                );
            }
        }
        for (start, tag, words) in [
            (SOURCE_FIRST, 65, 4096),
            (MASK_FIRST, 66, 4096),
            (CS_FIRST, 67, 512),
        ] {
            let context = pp::row(&d, start).unwrap();
            let salt = pp::row(&d, start + 1).unwrap();
            assert_eq!(id(context[pp::FLAGS + pp::FIRST]), 1);
            assert_eq!(id(context[pp::FLAGS + pp::CONTEXT]), 1);
            assert_eq!(id(salt[pp::FLAGS + pp::SALT]), 1);
            assert_eq!(id(context[pp::FLAGS + pp::PAYLOAD]), 0);
            assert_eq!(id(salt[pp::FLAGS + pp::PAYLOAD]), 0);
            for index in 0..words {
                let row = pp::row(&d, start + 2 + index / 8).unwrap();
                assert_eq!(id(row[index % 8]), pp::node(tag, index).unwrap());
            }
            let last = pp::row(&d, start + 1 + words / 8).unwrap();
            assert_eq!(id(last[pp::FLAGS + pp::LAST]), 1);
            assert_eq!(id(last[7]), pp::node(tag, words - 1).unwrap());
        }
        for word in 0..512 {
            let emit = pp::row(&d, RANGE_FIRST + 4 * word + 3).unwrap();
            assert_eq!(id(emit[34]), pp::node(67, word).unwrap());
            assert_eq!(id(emit[pp::COEFFICIENTS + 8]), 1u64 << 36);
        }
        let pad = pp::row(&d, HEIGHT - 1).unwrap();
        assert_eq!(pad.iter().filter(|&&v| v != Val::ZERO).count(), 1);
        assert_eq!(id(pad[pp::FLAGS + pp::PADDING]), 1);
        assert!(matches!(pp::row(&d, HEIGHT), Err(Error::Shape)));
        assert!(matches!(pp::node(67, 512), Err(Error::Shape)));
    }

    #[test]
    fn literal_request_rebinding_changes_expected_and_actual_native_prescreen_can_refuse() {
        let original = original();
        let d = Descriptor::unverified_geometry(original).unwrap();
        let n = u32::from_le_bytes(original.request_wire()[104..108].try_into().unwrap()) as usize;
        let mut nonce = original.binding();
        nonce[0] ^= 1;
        if nonce == [0; 32] {
            nonce[1] = 1;
        }
        let rebound = Statement::new(
            nonce,
            [
                original.request_wire()[112..112 + n].to_vec(),
                original.request_wire()[112 + n..].to_vec(),
            ],
            original.output_wire().to_vec(),
        )
        .unwrap();
        let other = Descriptor::unverified_geometry(&rebound).unwrap();
        assert_ne!(d.values, other.values);
        assert!(matches!(other.bound_claims(), Err(Error::Binding)));
        let air = ProgramAir::new(d).unwrap();
        assert_eq!(air.width(), WIDTH);
        assert_eq!(air.preprocessed_width(), PP_WIDTH);
        assert_eq!(air.num_public_values(), PUBLIC_VALUES);
        assert_eq!(
            air.main_next_row_columns(),
            (CHECKPOINT..=ACCUMULATOR).collect::<Vec<_>>()
        );
        assert!(air.preprocessed_next_row_columns().is_empty());
        // This executes the SAME full native symbolic/lookup/security derivation
        // used by the CLI, WITHOUT materializing preprocessed_trace or MAIN.
        // Security/resource refusal is a valid planning result, never proof success.
        match assessment::assess(&air) {
            Ok(report) => {
                report.log();
                match report.require_resources() {
                    Ok(()) | Err(Error::Resource) => {}
                    Err(error) => panic!("unexpected prescreen error: {error}"),
                }
            }
            Err(Error::Security) => {}
            Err(error) => panic!("invalid fixed descriptor/native metadata: {error}"),
        }
    }
}
