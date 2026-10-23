//! Genuine compiled-query evidence for the current confirmed BEGIN network case.
//! Public NONSECRET owner fixture; no Predicate is admitted or modelled as SQL.
use super::*;
use bfv_ciphertext_formation::gold::data;
use bfv_query_core::gold::{self, InputScope, Owner};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use registry200_joint::word::{Application, Control, Evidence, Request};
use registry200_proof::{
    Val,
    registry_progress::word as math,
    source,
    two_lane_encoding::{self as encoding, data_formation as installed, statement::KeyBinding},
};
use sha2::{Digest, Sha256};
use storage_client::word_query::{
    Actor, CompiledLockingSelect, CurrentMaterial, ImmutableEvidence,
};
use version_journal::Body;

fn fields(bytes: &[u8; 32]) -> [Val; 8] {
    source::statement::words(bytes)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}
fn public_bytes(words: &[u64]) -> [u8; 32] {
    assert_eq!(words.len(), 8);
    core::array::from_fn(|i| u32::try_from(words[i / 4]).unwrap().to_le_bytes()[i % 4])
}

pub struct Case {
    pub block: CandidateBlock,
    pub full_bytes: usize,
    pub compact_bytes: usize,
}
pub fn prepare(
    b: &Binding,
    begin: &CandidateBlock,
    history: &History,
    bank: Zeroizing<[u64; 208]>,
) -> Case {
    let source_expected = b.application_descriptor().source();
    let Body::Transition(begin_body) =
        Body::decode(begin.body(), &b.journal_genesis().profile).unwrap()
    else {
        panic!("BEGIN transition")
    };
    let begin_request = Request::decode(&begin_body.request).unwrap();
    assert_eq!(
        math::registry_root(&bank).unwrap(),
        begin_request.claims().next
    );
    assert_eq!(bank[84], 1, "the actual restored actor remains active");
    let snapshot = public_bytes(&bank[99..107]);
    let source_plain = fixture::original_source_bytes();
    let key = |cs| {
        KeyBinding::new(
            b.application_descriptor().database(),
            [0x73; 16],
            1,
            [0x95; 32],
            source::statement::encode_digest(cs),
        )
        .unwrap()
    };
    let owner = Owner::generate(
        [0x95; 32],
        installed::secret_context(&key([Val::ZERO; 4])).map(|v| v.as_canonical_u64()),
    )
    .unwrap();
    let encoding_expected = encoding::statement::Expected::source_version(
        source_expected,
        key(owner.key_expected().root_words().map(Val::from_u64)),
    )
    .unwrap();
    let witness = encoding::circuit::Witness::source_version(
        &encoding_expected,
        source_plain,
        [2; 4],
        [5; 4],
    )
    .unwrap();
    let mut data_words = witness.coefficients();
    assert_eq!(gold::SCALE * 41_392 % gold::T, 1);
    data_words
        .iter_mut()
        .for_each(|v| *v = *v * 41_392 % gold::T);
    // Encode ALL original rows without inspecting the SQL or selected rows.
    let original_data = owner.originate_data(data_words.clone()).unwrap();
    let data_request =
        data::Request::checked([0x61; 32], original_data.ciphertext().to_vec()).unwrap();
    let installed_expected =
        installed::Expected::checked(&data_request, &witness.statement()).unwrap();
    let state = source::hash::prove(
        source_expected,
        &source::circuit::Witness::new(
            [0x71; 32],
            [Val::ONE; 4],
            [Val::TWO; 4],
            [255, 0, 255, 128],
        ),
    )
    .unwrap();
    let child = encoding::hash::prove(&witness.statement(), &witness).unwrap();
    let data_frame = installed::hash::prove_prepared(
        &installed_expected,
        &data_request,
        installed::hash::Prerequisites::checked(&state, &child).unwrap(),
        owner
            .prepare_data(
                &original_data,
                installed_expected.core_expected(),
                Zeroizing::new([5; 4]),
            )
            .unwrap(),
    )
    .unwrap();

    let compiled = CompiledLockingSelect::compile(
        "SELECT age,amount FROM records WHERE age>=128 OFFSET 0 LIMIT 1 FOR UPDATE SKIP LOCKED",
    )
    .unwrap();
    let draft = math::Expected::checked(
        source_expected,
        math::Role::Predicate,
        b.journal_genesis().id().unwrap(),
        begin.header().id(),
        begin_request.enrollment(),
        math::Claims {
            old: begin_request.claims().next,
            command: [Val::ZERO; 4],
            statement: [Val::ZERO; 4],
            next: [Val::ZERO; 4],
            result: [Val::ZERO; 4],
            blind_sql: compiled.blinded_sql(),
        },
    )
    .unwrap();
    let prepared = compiled
        .prepare_current(
            &draft,
            CurrentMaterial {
                source: fixture::control_source(),
                registry: math::CurrentRegistry::new(
                    [fields(&[0x41; 32]), fields(&[0x42; 32])],
                    bank,
                    Zeroizing::new([7; 4]),
                )
                .unwrap(),
                actor: Actor {
                    slot: 0,
                    principal: 1,
                    transaction: 1,
                },
                walk: math::WalkInput {
                    client: fields(&[0x47; 32]),
                    call: 1,
                    invocation: fields(&[0xa9; 32]),
                    new_salt: [Val::from_u32(9); 4],
                    ..Default::default()
                },
                salts: Zeroizing::new([[3; 4], [4; 4], [5; 4]]),
            },
        )
        .unwrap();
    let (prepared, expected, opening) = prepared.into_parts();
    let (next, result) = opening.into_words();
    assert_eq!(math::registry_root(&next).unwrap(), expected.claims().next);
    assert_eq!(
        math::result_root(&result).unwrap(),
        expected.claims().result
    );
    let mut pending = prepared
        .originate(
            &owner,
            InputScope {
                database: b.application_descriptor().database(),
                transaction: 1,
                call: 1,
                principal: 1,
                application: math::profile_digest(),
                genesis: b.journal_genesis().id().unwrap(),
                rules: math::wire_profile_digest(),
                context: Sha256::digest(expected.binding()).into(),
                parent: begin.header().id(),
                client: [0x47; 32],
                controller: [0x41; 32],
                source_version: source_expected.version_id(),
                data_admission: Sha256::digest(installed_expected.core_expected().binding()).into(),
                snapshot,
                statement: source::statement::encode_digest(expected.claims().statement),
                command: source::statement::encode_digest(expected.claims().command),
                attempt: [0xa9; 32],
                nonce: [0xa9; 32],
            },
            &expected,
            &installed_expected,
        )
        .unwrap();
    let producer = math::hash::Prover::new().unwrap();
    let proved = pending
        .prove_public(&owner, &producer, &expected, &installed_expected)
        .unwrap();
    // Actual SDK arithmetic, not an encrypted fixture answer. This particular
    // transport gate's evaluator is LOCAL; remote FHE execution is not claimed.
    let response = gold::Evaluator::new()
        .unwrap()
        .evaluate(proved.public_request())
        .unwrap();
    let read = math::read::Expected::checked(
        &expected,
        &installed_expected,
        &proved.public_request().formation_request().unwrap(),
        proved.query_expected().core_expected().roots()[0],
        response.output().to_vec(),
    )
    .unwrap();
    let packet = proved
        .packet(
            &read,
            ImmutableEvidence {
                state: &state,
                child: &child,
                data: &data_frame,
            },
            response.certificate(),
        )
        .unwrap();
    // Independent native all-six check makes fixture validity observable before
    // testing the separate network admission rejection. It is not a grant.
    let receiving = math::read::hash::Verifier::new(&read).unwrap();
    let parsed = registry200_joint::word::predicate::BorrowedPredicate::parse(
        source_expected,
        packet.as_bytes(),
    )
    .unwrap();
    let (checked, _) = receiving.verify_and_retain(parsed.evidence()).unwrap();
    let decrypted = proved.complete(&owner, &checked).unwrap();
    let mut oracle = Zeroizing::new(vec![0u64; gold::N]);
    for (i, &v) in data_words.iter().enumerate().filter(|(_, v)| **v != 0) {
        for j in 0..128 {
            oracle[i + j] = (oracle[i + j] + v) % gold::T;
        }
    }
    assert_eq!(
        decrypted.coefficients(),
        oracle.as_slice(),
        "all4096 actual FHE coefficients"
    );

    let app = Application::new(b.application_descriptor().clone(), b.journal_genesis()).unwrap();
    let request = Request::predicate(
        &app,
        begin.header().id(),
        [0xb1; 32],
        begin_request.enrollment(),
        expected.claims(),
    )
    .unwrap();
    let evidence = Evidence::predicate(&packet).unwrap();
    let mut transition = version_journal::AuthorizedTransition {
        parent: begin.header().id(),
        request: request.encode(),
        updates: vec![version_journal::ShardUpdate {
            id: b.application_descriptor().control_id(),
            old: Control::Active {
                enrollment: request.enrollment(),
                registry: expected.claims().old,
            }
            .heads(b.application_descriptor()),
            new: Control::Active {
                enrollment: request.enrollment(),
                registry: expected.claims().next,
            }
            .heads(b.application_descriptor()),
        }],
        proof: evidence.into_bytes(),
        owner_signature: [0; 64],
    };
    transition.sign(app.genesis(), &fixture::control_owner_key());
    let body = Body::Transition(transition);
    let mut header = history
        .candidate_header(&body, begin.header().timestamp + 1, 1_000_000)
        .unwrap();
    header.mine(16).unwrap();
    let block =
        CandidateBlock::new(header, body.encode(&b.journal_genesis().profile).unwrap()).unwrap();
    let compact = registry200_finality::word::transport::compact_body(b, &block).unwrap();
    assert!(compact.len() < block.body().len());
    Case {
        full_bytes: block.body().len(),
        compact_bytes: compact.len(),
        block,
    }
}

/// A freshly signed full Body with the SAME metadata/lengths but changed omitted
/// bytes. Only exact original full-body authentication must reject its compact form.
pub fn changed_immutable_body(b: &Binding, original: &CandidateBlock) -> CandidateBlock {
    let Body::Transition(mut body) =
        Body::decode(original.body(), &b.journal_genesis().profile).unwrap()
    else {
        panic!("Predicate transition")
    };
    let packet = 24usize;
    let len = |i: usize| {
        u32::from_le_bytes(
            body.proof[packet + 376 + 4 * i..packet + 380 + 4 * i]
                .try_into()
                .unwrap(),
        ) as usize
    };
    let state_at = packet + 416 + len(0) + len(1);
    let last_state = state_at + len(2) - 1;
    body.proof[last_state] ^= 1;
    body.sign(original.header().genesis, &fixture::control_owner_key());
    let bytes = Body::Transition(body)
        .encode(&b.journal_genesis().profile)
        .unwrap();
    let mut header = original.header().clone();
    header.body_hash = version_journal::hash(&bytes);
    header.nonce = 0;
    header.mine(16).unwrap();
    CandidateBlock::new(header, bytes).unwrap()
}
