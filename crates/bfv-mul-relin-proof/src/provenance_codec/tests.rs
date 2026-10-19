//! Public metadata codec tests. Generated BFV keys/CTs are nonsecret fixtures;
//! compact ciphertext geometry and Key/Encoding roots below are UNPROVED claims.
use super::*;
use crate::{INPUT_FRAMES, InputEvidence, MAX_INPUT_BYTES, input_frame_limit};
use bfv_query_core::{CoefficientRow, Geometry, KeyScope, Owner, QueryContext};
use sha2::Sha512;
use std::sync::OnceLock;

const SOURCE_AT: usize = 168 + BfvKeyAnchor::CLAIM_BYTES;
const SOURCE_ROOTS: usize = SOURCE_AT + 32 + 224 + 60 + 2384;
const KEY_AT: usize = SOURCE_AT + SOURCE_BYTES;
const CS_AT: usize = KEY_AT + 68;
const TRANSFORMED_AT: usize = CS_AT + 32;
const SOURCE_CW_AT: usize = KEY_AT + KEY_BYTES;
const SQL_AT: usize = SOURCE_CW_AT + 32;
const NONCE_AT: usize = SQL_AT + 32;
const MASK_AT: usize = NONCE_AT + 32;
const QUERY_CW_AT: usize = MASK_AT + 32;

fn snapshot(
    schema: [u8; 16],
    width: u32,
    per_page: u32,
    rows: u64,
    packet_len: usize,
) -> ([u8; 112], Vec<u8>) {
    // A bounded canonical PUBLIC ciphertext image, not a valid AEAD/logical-index
    // opening. No tests credit this fixture as a Source cryptographic proof.
    let mut head = [0; 112];
    head[..8].copy_from_slice(b"CSTORE01");
    head[8..24].fill(0x42);
    head[24..40].fill(0x61);
    head[40..56].copy_from_slice(&schema);
    head[64..68].copy_from_slice(&width.to_le_bytes());
    head[68..72].copy_from_slice(&per_page.to_le_bytes());
    head[72..80].copy_from_slice(&rows.to_le_bytes());
    let mut packet = vec![0xA3; packet_len];
    packet[..8].fill(0);
    let mut leaf = Sha256::new();
    leaf.update(b"compact-store/leaf/v1");
    leaf.update(0u64.to_le_bytes());
    leaf.update((packet_len as u64).to_le_bytes());
    leaf.update(&packet);
    let mut root = Sha256::new();
    root.update(b"compact-store/snapshot/v1");
    root.update(&head[..80]);
    root.update(leaf.finalize());
    head[80..].copy_from_slice(&root.finalize());
    (head, packet)
}

fn fixture() -> &'static Provenance {
    static PUBLIC: OnceLock<Provenance> = OnceLock::new();
    PUBLIC.get_or_init(|| {
        let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
        let anchor = owner
            .key_anchor(
                &setup,
                KeyScope {
                    database: [0x42; 16],
                    bfv_key_domain: [0x71; 16],
                    epoch: 9,
                },
            )
            .unwrap()
            .public_anchor()
            .clone();
        let data = snapshot(source::DATA_SCHEMA, 3, 256, 4, 60);
        let index = snapshot(source::INDEX_SCHEMA, 1, 4096, 2336, 2384);
        let query = [0xE7; 32];
        let source = CanonicalSource::checked_claim(&source::Statement {
            relation: Relation::CanonicalIndex,
            request: query,
            heads: [data.0, index.0],
            packets: [data.1, index.1],
            key_commitment: [Val::from_u8(5); 4],
            open_commitment: [Val::from_u8(6); 4],
        })
        .unwrap();
        let parameters = setup.relinearization_material().unwrap();
        let key = bfv_key_transform::Statement {
            expected: bfv_key_transform::Expected {
                descriptor: bfv_key_transform::SetupDescriptor {
                    database: anchor.scope().database,
                    key_domain: anchor.scope().bfv_key_domain,
                    public_setup_digest: Sha256::digest(parameters.parameters()).into(),
                    key_epoch: anchor.scope().epoch,
                },
                coefficients: anchor.coefficient_commitment().map(Val::from_u64),
            },
            transformed: [Val::from_u8(7); 4],
        };
        let binding = BfvBinding::new(anchor.full_setup_id(), key);
        let encodings = [
            Statement {
                expected: Expected::source(&source, binding.clone()).unwrap(),
                encoded: [Val::from_u8(8); 4],
            },
            Statement {
                expected: Expected::private_mask(
                    &source,
                    binding,
                    [0x81; 32],
                    [0x82; 32],
                    source::statement::encode_digest([Val::from_u8(9); 4]),
                )
                .unwrap(),
                encoded: [Val::from_u8(10); 4],
            },
        ];
        let rows = [
            CoefficientRow { age: 0, amount: 0 },
            CoefficientRow {
                age: 255,
                amount: 65535,
            },
            CoefficientRow {
                age: 73,
                amount: 4095,
            },
            CoefficientRow {
                age: 128,
                amount: 256,
            },
        ];
        let original = owner
            .encrypt_original_coefficient_rows_for_experiment(&rows)
            .unwrap();
        let prepared = owner
            .prepare_private_coefficient_predicate_for_experiment(
                QueryContext::new([0x22; 16], data.0, index.0),
                query,
                &original,
                &[0xA5; 32],
            )
            .unwrap();
        let ciphertexts = prepared.operand_ciphertexts().unwrap().map(<[u8]>::to_vec);
        Provenance::new(setup, anchor, encodings, ciphertexts).unwrap()
    })
}
fn identity(p: &Provenance) -> [u8; 64] {
    let mut h = Sha512::new();
    p.feed_identity(&mut h);
    h.finalize().into()
}
fn decode(bytes: &[u8]) -> Result<Provenance> {
    Provenance::decode_claim(fixture().setup().clone(), bytes)
}

#[test]
fn public_provenance_claim_roundtrips_complete_inputs_and_identity_without_output_or_proofs() {
    let original = fixture();
    let bytes = original.encode_claim().unwrap();
    assert_eq!(HEADER, 3372);
    assert_eq!(
        bytes.len(),
        HEADER + original.ciphertexts().iter().map(Vec::len).sum::<usize>()
    );
    assert!(bytes.len() <= MAX_PROVENANCE_CLAIM_BYTES);
    let decoded = decode(&bytes).unwrap();
    assert_eq!(decoded.encode_claim().unwrap(), bytes);
    assert_eq!(decoded.anchor(), original.anchor());
    assert_eq!(decoded.query(), original.query());
    assert_eq!(decoded.ciphertexts(), original.ciphertexts());
    assert_eq!(identity(&decoded), identity(original));
    for (left, right) in decoded.encodings().iter().zip(original.encodings()) {
        assert_eq!(left.values(), right.values());
        assert_eq!(
            left.expected.source_claim().heads,
            right.expected.source_claim().heads
        );
        assert_eq!(
            left.expected.source_claim().packets,
            right.expected.source_claim().packets
        );
        assert_eq!(left.producer_identity(), right.producer_identity());
    }
    // Well-framed garbage is still not evidence; the real verifier must run.
    let dummy = [1u8];
    let evidence = InputEvidence::from_frames([&dummy; INPUT_FRAMES]).unwrap();
    assert_eq!(
        decoded.verify_inputs(&evidence),
        Err(Error::InputVerification)
    );
}

#[test]
fn provenance_decode_rejects_namespace_setup_geometry_roots_lengths_and_trailing_bytes() {
    let bytes = fixture().encode_claim().unwrap();
    for length in [0, 7, HEADER - 1, bytes.len() - 1] {
        assert!(decode(&bytes[..length]).is_err());
    }
    let mut oversized = vec![0; MAX_PROVENANCE_CLAIM_BYTES + 1];
    oversized[..8].copy_from_slice(MAGIC);
    assert!(matches!(decode(&oversized), Err(Error::ResourceLimit)));
    for offset in [0, 8, 39, 40, 71, 72, 103, 104, 167, 168] {
        let mut wrong = bytes.clone();
        wrong[offset] ^= 1;
        assert!(decode(&wrong).is_err(), "namespace/setup offset {offset}");
    }
    for offset in [
        SOURCE_AT + 32,
        SOURCE_AT + 32 + 112,
        SOURCE_AT + 32 + 224 + 59,
        SOURCE_ROOTS - 1,
        KEY_AT,
        KEY_AT + 16,
        KEY_AT + 32,
        KEY_AT + 67,
        CS_AT,
    ] {
        let mut wrong = bytes.clone();
        wrong[offset] ^= 1;
        assert!(
            decode(&wrong).is_err(),
            "association/geometry offset {offset}"
        );
    }
    for offset in [
        SOURCE_ROOTS,
        SOURCE_ROOTS + 32,
        CS_AT,
        TRANSFORMED_AT,
        SOURCE_CW_AT,
        MASK_AT,
        QUERY_CW_AT,
    ] {
        for word in 0..4 {
            let mut alias = bytes.clone();
            alias[offset + 8 * word..offset + 8 * word + 8]
                .copy_from_slice(&Val::ORDER_U64.to_le_bytes());
            assert!(matches!(decode(&alias), Err(Error::Statement)));
        }
    }
    for offset in [HEADER - 8, HEADER - 4] {
        for length in [
            0u32,
            u32::MAX,
            bfv_ciphertext_wire::MAX_CIPHERTEXT_BYTES as u32 + 1,
        ] {
            let mut bad = bytes.clone();
            bad[offset..offset + 4].copy_from_slice(&length.to_le_bytes());
            assert!(matches!(decode(&bad), Err(Error::ResourceLimit)));
        }
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(decode(&trailing).is_err());
    let mut malformed = bytes;
    malformed[HEADER] ^= 1;
    assert!(decode(&malformed).is_err());
}

#[test]
fn coherent_foreign_public_claims_change_full_identity_and_never_replace_local_pins() {
    let original = fixture();
    let bytes = original.encode_claim().unwrap();
    // These are valid DIFFERENT mathematical labels, not proof forgeries. No
    // checksum can reject them in isolation; the client keeps its local Expected.
    for offset in [
        SOURCE_AT,
        SOURCE_AT + 31,
        TRANSFORMED_AT,
        TRANSFORMED_AT + 24,
        SOURCE_CW_AT,
        SQL_AT,
        SQL_AT + 31,
        NONCE_AT,
        MASK_AT,
        QUERY_CW_AT,
    ] {
        let mut foreign = bytes.clone();
        foreign[offset] ^= 1;
        let other = decode(&foreign).unwrap();
        assert_ne!(
            identity(&other),
            identity(original),
            "full association offset {offset}"
        );
        assert!(
            other
                .encodings()
                .iter()
                .zip(original.encodings())
                .any(|(left, right)| left.values() != right.values())
        );
    }
    // Swapping two genuine canonical CTs passes grammar but changes the exact
    // ordered identity; it cannot satisfy original Formation prerequisites.
    let mut swapped = bytes[..HEADER].to_vec();
    swapped[HEADER - 8..HEADER - 4]
        .copy_from_slice(&(original.ciphertexts()[1].len() as u32).to_le_bytes());
    swapped[HEADER - 4..HEADER]
        .copy_from_slice(&(original.ciphertexts()[0].len() as u32).to_le_bytes());
    swapped.extend_from_slice(&original.ciphertexts()[1]);
    swapped.extend_from_slice(&original.ciphertexts()[0]);
    assert_ne!(identity(&decode(&swapped).unwrap()), identity(original));
    let mut foreign_anchor = bytes; // Cs and matching Key Cs change together.
    let next = if original.anchor().coefficient_commitment()[0] == 0 {
        1u64
    } else {
        0u64
    };
    for offset in [168 + 108, CS_AT] {
        foreign_anchor[offset..offset + 8].copy_from_slice(&next.to_le_bytes());
    }
    let other = decode(&foreign_anchor).unwrap();
    assert_ne!(other.anchor(), original.anchor());
    assert_ne!(identity(&other), identity(original));
}

#[test]
fn input_frame_helpers_preserve_all_fifteen_roles_caps_and_borrowed_bytes() {
    let owned: [Vec<u8>; INPUT_FRAMES] = core::array::from_fn(|i| vec![i as u8 + 1; i + 1]);
    let frames = owned.each_ref().map(Vec::as_slice);
    let evidence = InputEvidence::from_frames(frames).unwrap();
    assert_eq!(evidence.frames(), frames);
    for (left, right) in evidence.frames().iter().zip(frames) {
        assert!(core::ptr::eq(*left, right));
    }
    assert_eq!(evidence.key, frames[0]);
    assert_eq!(evidence.encodings, [frames[1], frames[2]]);
    assert_eq!(evidence.bases[0], frames[3..8]);
    assert_eq!(evidence.bases[1], frames[8..13]);
    assert_eq!(evidence.formations, [frames[13], frames[14]]);
    assert_eq!(
        evidence.byte_len().unwrap(),
        owned.iter().map(Vec::len).sum::<usize>()
    );
    assert_eq!(
        (0..INPUT_FRAMES)
            .map(|i| input_frame_limit(i).unwrap())
            .sum::<usize>(),
        MAX_INPUT_BYTES
    );
    assert_eq!(input_frame_limit(INPUT_FRAMES), None);
    assert_eq!(input_frame_limit(usize::MAX), None);
    for ordinal in 0..INPUT_FRAMES {
        let mut missing = frames;
        missing[ordinal] = &[];
        assert!(matches!(
            InputEvidence::from_frames(missing),
            Err(Error::ResourceLimit)
        ));
    }
    // One allocation at a time: helper enforces each of the four existing caps.
    for ordinal in [0, 1, 3, 13] {
        let over = vec![0; input_frame_limit(ordinal).unwrap() + 1];
        let mut hostile = frames;
        hostile[ordinal] = &over;
        assert!(matches!(
            InputEvidence::from_frames(hostile),
            Err(Error::ResourceLimit)
        ));
    }
    // Preserve old byte_len semantics for direct callers; it remains a size
    // counter, while from_frames explicitly refuses absent network frames.
    let empty = InputEvidence {
        key: &[],
        encodings: [&[]; 2],
        bases: [[&[]; 5]; 2],
        formations: [&[]; 2],
    };
    assert_eq!(empty.byte_len().unwrap(), 0);
}
