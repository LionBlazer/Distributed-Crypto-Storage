//! All signing keys and easy targets below are PUBLIC, NON-SECRET test fixtures.
use ed25519_dalek::{
    SigningKey,
    hazmat::{ExpandedSecretKey, raw_sign},
};
use sha2::{Digest, Sha512};

use crate::*;

fn key(index: u8) -> SigningKey {
    SigningKey::from_bytes(&[index; 32])
}
fn seed(domain: u8, tickets: u32, validators: u32) -> NetworkSeed {
    let mut target = [0xff; 32];
    target[0] = 0x3f;
    NetworkSeed::new(
        [domain; 32],
        [7; 32],
        target,
        Limits::new(tickets, validators).unwrap(),
    )
    .unwrap()
}
fn tickets(election: &Election, index: u8, count: usize) -> Vec<WorkTicket> {
    let signer = key(index);
    let mut next = 0;
    (0..count)
        .map(|_| {
            let ticket = WorkTicket::mine(election, &signer, next, 4096).unwrap();
            next = ticket.nonce().checked_add(1).unwrap();
            ticket
        })
        .collect()
}
fn fixture_genesis(domain: u8, weights: &[(u8, usize)]) -> Genesis {
    let config = seed(domain, 32, 16);
    let election = config.bootstrap_election();
    let claims = weights
        .iter()
        .flat_map(|&(index, count)| tickets(&election, index, count))
        .collect();
    Genesis::from_bootstrap(config, claims).unwrap()
}
fn context(set: &EpochSet, round: u64, step: Step, value: Option<Hash>) -> VoteContext {
    VoteContext::new(set, [91; 32], 1, round, step, value).unwrap()
}
fn signed(context: VoteContext, indices: &[u8]) -> Vec<SignedVote> {
    indices
        .iter()
        .map(|&i| SignedVote::sign(context, &key(i)).unwrap())
        .collect()
}
fn fixture_certificate(genesis: &Genesis) -> (VoteContext, QuorumCertificate) {
    let expected = context(genesis.initial_set(), 0, Step::Precommit, Some([31; 32]));
    let votes = signed(expected, &[1, 2]);
    let certificate =
        QuorumCertificate::assemble(genesis.initial_set(), &expected, &votes).unwrap();
    (expected, certificate)
}

#[test]
fn bootstrap_derives_exact_work_weights_and_requires_an_independent_genesis_pin() {
    let original = fixture_genesis(1, &[(1, 3), (2, 1)]);
    let bytes = original.encode().unwrap();
    let restored = Genesis::decode(&bytes, original.id()).unwrap();
    assert_eq!(restored, original);
    assert_eq!(restored.initial_set().network_id(), original.id());
    assert_eq!(restored.initial_set().total_work_units(), 4);
    assert_eq!(
        restored
            .initial_set()
            .weight(key(1).verifying_key().to_bytes()),
        Some(3)
    );
    assert_eq!(
        restored
            .initial_set()
            .weight(key(2).verifying_key().to_bytes()),
        Some(1)
    );
    assert_eq!(bytes.len(), 188 + 4 * TICKET_BYTES);
    assert_eq!(Genesis::decode(&bytes, [0; 32]), Err(Error::WrongDomain));
    // Tickets used SeedId before FinalityId existed; no self-referential opening.
    for ticket in restored.bootstrap_tickets() {
        ticket
            .verify(&restored.seed().bootstrap_election())
            .unwrap();
    }
}

#[test]
fn splitting_fixed_difficulty_work_between_identities_does_not_add_weight() {
    let one_identity = fixture_genesis(2, &[(1, 3)]);
    let three_identities = fixture_genesis(2, &[(1, 1), (2, 1), (3, 1)]);
    assert_eq!(one_identity.initial_set().validators().len(), 1);
    assert_eq!(three_identities.initial_set().validators().len(), 3);
    assert_eq!(one_identity.initial_set().total_work_units(), 3);
    assert_eq!(three_identities.initial_set().total_work_units(), 3);
}

#[test]
fn two_genuinely_valid_signatures_of_the_same_pow_cannot_mint_two_work_units() {
    let config = seed(3, 4, 4);
    let election = config.bootstrap_election();
    let signer = key(1);
    let ticket = tickets(&election, 1, 1).pop().unwrap();
    let pow_id = ticket.pow_id(&election).unwrap();
    let message = crate::hash(b"dcs/work-finality/ticket-possession/v1", &[&pow_id]);
    // A malicious holder may choose another Ed25519 nonce prefix. Use the
    // existing library's hazmat API ONLY for this explicitly non-secret test.
    let expanded_bytes: [u8; 64] = Sha512::digest(signer.to_bytes()).into();
    let mut expanded = ExpandedSecretKey::from_bytes(&expanded_bytes);
    expanded.hash_prefix[0] ^= 0x80;
    let signature = raw_sign::<Sha512>(&expanded, &message, &signer.verifying_key());
    let mut bytes = ticket.encode();
    bytes[153..].copy_from_slice(&signature.to_bytes());
    let alternative = WorkTicket::decode(&election, &bytes).unwrap();
    ticket.verify(&election).unwrap();
    alternative.verify(&election).unwrap();
    assert_ne!(ticket.encode(), alternative.encode());
    assert_eq!(ticket.pow_id(&election), alternative.pow_id(&election));
    assert_eq!(
        Genesis::from_bootstrap(config, vec![ticket, alternative]),
        Err(Error::DuplicateTicket)
    );
}

#[test]
fn valid_work_and_possession_are_both_required_for_the_exact_election() {
    let config = seed(4, 8, 8);
    let election = config.bootstrap_election();
    let mut originals = tickets(&election, 1, 2);
    let first = originals.remove(0);
    let second = originals.remove(0);
    first.verify(&election).unwrap();
    let mut wrong_signature = second.encode();
    wrong_signature[153..].copy_from_slice(&first.encode()[153..]);
    assert_eq!(
        WorkTicket::decode(&election, &wrong_signature),
        Err(Error::InvalidSignature)
    );

    let other_key = tickets(&election, 2, 1).pop().unwrap();
    let mut relabeled = other_key.encode();
    relabeled[153..].copy_from_slice(&first.encode()[153..]);
    assert_eq!(
        WorkTicket::decode(&election, &relabeled),
        Err(Error::InvalidSignature)
    );
    assert_eq!(
        first.verify(&seed(5, 8, 8).bootstrap_election()),
        Err(Error::WrongDomain)
    );

    let mut invalid_work = first.encode();
    let nonce = (0..4096)
        .find(|&n| !election.permits(first.public_key(), n))
        .unwrap();
    invalid_work[145..153].copy_from_slice(&nonce.to_le_bytes());
    assert_eq!(
        WorkTicket::decode(&election, &invalid_work),
        Err(Error::InvalidWork)
    );
    let mut weak = first.encode();
    let nonce = (0..4096).find(|&n| election.permits([0; 32], n)).unwrap();
    weak[113..145].fill(0);
    weak[145..153].copy_from_slice(&nonce.to_le_bytes());
    assert_eq!(WorkTicket::decode(&election, &weak), Err(Error::InvalidKey));
}

#[test]
fn mining_attempt_and_nonce_exhaustion_stop_without_wrapping() {
    let mut hard_target = [0; 32];
    hard_target[31] = 1;
    let seed =
        NetworkSeed::new([9; 32], [10; 32], hard_target, Limits::new(1, 1).unwrap()).unwrap();
    let election = seed.bootstrap_election();
    let signer = key(1);
    assert!(!election.permits(signer.verifying_key().to_bytes(), u64::MAX));
    assert_eq!(
        WorkTicket::mine(&election, &signer, 0, 0),
        Err(Error::MiningExhausted)
    );
    assert_eq!(
        WorkTicket::mine(&election, &signer, u64::MAX, 2),
        Err(Error::MiningExhausted)
    );
    assert_eq!(
        WorkTicket::sign(&election, &signer, u64::MAX),
        Err(Error::InvalidWork)
    );
}

#[test]
fn successor_sets_bind_epoch_and_challenge_but_do_not_certify_the_handoff() {
    let genesis = fixture_genesis(6, &[(1, 1), (2, 1)]);
    let election = genesis.election(1, [44; 32]).unwrap();
    let claims = tickets(&election, 3, 2);
    let set = genesis
        .derive_epoch_set(1, [44; 32], claims.clone())
        .unwrap();
    assert_eq!(set.epoch(), 1);
    assert_eq!(set.network_id(), genesis.id());
    assert_eq!(set.total_work_units(), 2);
    assert_eq!(
        genesis.derive_epoch_set(2, [44; 32], claims.clone()),
        Err(Error::WrongDomain)
    );
    assert_eq!(
        genesis.derive_epoch_set(1, [45; 32], claims),
        Err(Error::WrongDomain)
    );
    assert_eq!(genesis.election(0, [44; 32]), Err(Error::InvalidConfig));
    assert_eq!(
        genesis.derive_epoch_set(1, [44; 32], genesis.bootstrap_tickets().to_vec()),
        Err(Error::WrongDomain)
    );
}

#[test]
fn exact_two_thirds_is_not_a_quorum_and_work_weight_is_not_signer_count() {
    let genesis = fixture_genesis(7, &[(1, 2), (2, 1)]);
    let set = genesis.initial_set();
    let expected = context(set, 0, Step::Precommit, Some([33; 32]));
    let heavy = signed(expected, &[1]);
    heavy[0].verify(set, &expected).unwrap();
    assert_eq!(
        QuorumCertificate::assemble(set, &expected, &heavy),
        Err(Error::NoQuorum)
    );
    let quorum = QuorumCertificate::assemble(set, &expected, &signed(expected, &[1, 2])).unwrap();
    assert_eq!(quorum.signed_work_units(), 3);
    quorum.verify(set, &expected).unwrap();

    let skewed = fixture_genesis(8, &[(1, 3), (2, 1)]);
    let set = skewed.initial_set();
    let expected = context(set, 0, Step::Prevote, Some([33; 32]));
    let quorum = QuorumCertificate::assemble(set, &expected, &signed(expected, &[1])).unwrap();
    assert_eq!(quorum.signer_count(), 1);
    assert_eq!(quorum.signed_work_units(), 3);
    assert_eq!(
        QuorumCertificate::assemble(set, &expected, &signed(expected, &[2])),
        Err(Error::NoQuorum)
    );
    // This is arithmetic only; the large holder going offline stops progress.
}

#[test]
fn nil_votes_are_valid_messages_but_never_non_nil_quorum_evidence() {
    let genesis = fixture_genesis(9, &[(1, 1), (2, 1)]);
    let set = genesis.initial_set();
    for step in [Step::Prevote, Step::Precommit] {
        let nil = context(set, 0, step, None);
        let votes = signed(nil, &[1, 2]);
        let bytes = votes[0].encode();
        SignedVote::decode_and_verify(set, &nil, &bytes).unwrap();
        assert_eq!(
            QuorumCertificate::assemble(set, &nil, &votes),
            Err(Error::NilValue)
        );
        let zero_hash = context(set, 0, step, Some([0; 32]));
        assert_eq!(votes[0].verify(set, &zero_hash), Err(Error::MixedVotes));
        QuorumCertificate::assemble(set, &zero_hash, &signed(zero_hash, &[1, 2])).unwrap();
    }
    assert_eq!(
        VoteContext::new(set, [91; 32], 0, 0, Step::Prevote, None),
        Err(Error::InvalidConfig)
    );
}

#[test]
fn certificates_never_merge_round_slot_step_journal_or_value_votes() {
    let genesis = fixture_genesis(10, &[(1, 1), (2, 1)]);
    let set = genesis.initial_set();
    let (expected, certificate) = fixture_certificate(&genesis);
    let mut last_journal_byte = [91; 32];
    last_journal_byte[31] ^= 1;
    let mut last_value_byte = expected.value().unwrap();
    last_value_byte[31] ^= 1;
    let alternatives = [
        context(set, 1, Step::Precommit, expected.value()),
        context(set, 1u64 << 32, Step::Precommit, expected.value()),
        VoteContext::new(set, [91; 32], 2, 0, Step::Precommit, expected.value()).unwrap(),
        VoteContext::new(
            set,
            [91; 32],
            1 + (1u64 << 32),
            0,
            Step::Precommit,
            expected.value(),
        )
        .unwrap(),
        context(set, 0, Step::Prevote, expected.value()),
        VoteContext::new(
            set,
            last_journal_byte,
            1,
            0,
            Step::Precommit,
            expected.value(),
        )
        .unwrap(),
        context(set, 0, Step::Precommit, Some(last_value_byte)),
    ];
    for alternative in alternatives {
        let votes = [
            SignedVote::sign(expected, &key(1)).unwrap(),
            SignedVote::sign(alternative, &key(2)).unwrap(),
        ];
        assert_eq!(
            QuorumCertificate::assemble(set, &expected, &votes),
            Err(Error::MixedVotes)
        );
        assert_eq!(
            certificate.verify(set, &alternative),
            Err(Error::MixedVotes)
        );
        // Repair the complete public header to the independently changed context.
        // Every retained signature is now invalid; a repaired envelope is no bypass.
        let repaired =
            QuorumCertificate::assemble(set, &alternative, &signed(alternative, &[1, 2]))
                .unwrap()
                .encode()
                .unwrap();
        let mut hostile = certificate.encode().unwrap();
        hostile[..CERTIFICATE_HEADER_BYTES].copy_from_slice(&repaired[..CERTIFICATE_HEADER_BYTES]);
        assert_eq!(
            QuorumCertificate::decode_and_verify(set, &alternative, &hostile),
            Err(Error::InvalidSignature)
        );
    }
}

#[test]
fn genuine_foreign_network_and_epoch_quorums_do_not_cross_independent_contexts() {
    let first = fixture_genesis(11, &[(1, 1), (2, 1)]);
    let foreign = fixture_genesis(12, &[(1, 1), (2, 1)]);
    let (expected, certificate) = fixture_certificate(&first);
    let (foreign_expected, foreign_certificate) = fixture_certificate(&foreign);
    foreign_certificate
        .verify(foreign.initial_set(), &foreign_expected)
        .unwrap();
    assert_eq!(
        QuorumCertificate::decode_and_verify(
            first.initial_set(),
            &expected,
            &foreign_certificate.encode().unwrap()
        ),
        Err(Error::MixedVotes)
    );

    let e = first.election(1, [55; 32]).unwrap();
    let mut claims = tickets(&e, 1, 1);
    claims.extend(tickets(&e, 2, 1));
    let successor = first.derive_epoch_set(1, [55; 32], claims).unwrap();
    let next = context(&successor, 0, Step::Precommit, expected.value());
    let genuine = QuorumCertificate::assemble(&successor, &next, &signed(next, &[1, 2])).unwrap();
    genuine.verify(&successor, &next).unwrap();
    assert_eq!(
        genuine.verify(first.initial_set(), &expected),
        Err(Error::MixedVotes)
    );
    assert_eq!(
        certificate.verify(&successor, &expected),
        Err(Error::WrongDomain)
    );
}

#[test]
fn repeated_signers_outsiders_and_bad_signatures_never_add_weight() {
    let genesis = fixture_genesis(13, &[(1, 1), (2, 1)]);
    let set = genesis.initial_set();
    let (expected, certificate) = fixture_certificate(&genesis);
    let vote = SignedVote::sign(expected, &key(1)).unwrap();
    assert_eq!(
        QuorumCertificate::assemble(set, &expected, &[vote.clone(), vote]),
        Err(Error::DuplicateSigner)
    );
    let outsider = SignedVote::sign(expected, &key(3)).unwrap();
    assert_eq!(outsider.verify(set, &expected), Err(Error::UnknownSigner));
    let mut bytes = certificate.encode().unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    assert_eq!(
        QuorumCertificate::decode_and_verify(set, &expected, &bytes),
        Err(Error::InvalidSignature)
    );
}

#[test]
fn canonical_certificate_decode_rejects_reordered_duplicated_truncated_and_trailing_records() {
    let genesis = fixture_genesis(14, &[(1, 1), (2, 1)]);
    let set = genesis.initial_set();
    let (expected, certificate) = fixture_certificate(&genesis);
    let bytes = certificate.encode().unwrap();
    assert_eq!(
        QuorumCertificate::decode_and_verify(set, &expected, &bytes).unwrap(),
        certificate
    );
    for end in 0..bytes.len() {
        assert!(QuorumCertificate::decode_and_verify(set, &expected, &bytes[..end]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        QuorumCertificate::decode_and_verify(set, &expected, &trailing),
        Err(Error::InvalidEncoding)
    );
    let mut reversed = bytes.clone();
    reversed[CERTIFICATE_HEADER_BYTES..].rotate_left(ENDORSEMENT_BYTES);
    assert_eq!(
        QuorumCertificate::decode_and_verify(set, &expected, &reversed),
        Err(Error::DuplicateSigner)
    );
    let mut duplicated = bytes.clone();
    duplicated[CERTIFICATE_HEADER_BYTES + ENDORSEMENT_BYTES..].copy_from_slice(
        &bytes[CERTIFICATE_HEADER_BYTES..CERTIFICATE_HEADER_BYTES + ENDORSEMENT_BYTES],
    );
    assert_eq!(
        QuorumCertificate::decode_and_verify(set, &expected, &duplicated),
        Err(Error::DuplicateSigner)
    );
}

#[test]
fn remote_counts_and_total_caps_are_rejected_before_record_allocation() {
    let genesis = fixture_genesis(15, &[(1, 1), (2, 1)]);
    let set = genesis.initial_set();
    let (expected, certificate) = fixture_certificate(&genesis);
    let mut cert = certificate.encode().unwrap();
    cert[193..197].copy_from_slice(&u32::MAX.to_le_bytes());
    cert.truncate(CERTIFICATE_HEADER_BYTES);
    assert_eq!(
        QuorumCertificate::decode_and_verify(set, &expected, &cert),
        Err(Error::ResourceLimit)
    );
    assert_eq!(
        QuorumCertificate::decode_and_verify(set, &expected, &vec![0; MAX_CERTIFICATE_BYTES + 1]),
        Err(Error::ResourceLimit)
    );
    let mut packet = genesis.encode().unwrap();
    packet[184..188].copy_from_slice(&u32::MAX.to_le_bytes());
    packet.truncate(188);
    assert_eq!(
        Genesis::decode(&packet, genesis.id()),
        Err(Error::ResourceLimit)
    );
    assert_eq!(
        Genesis::decode(&vec![0; MAX_GENESIS_BYTES + 1], genesis.id()),
        Err(Error::ResourceLimit)
    );
    assert_eq!(
        crate::wire::length(1, usize::MAX, 2, usize::MAX),
        Err(Error::ResourceLimit)
    );
}

#[test]
fn genesis_and_fixed_message_codecs_enforce_profiles_order_lengths_and_last_bytes() {
    let genesis = fixture_genesis(16, &[(1, 1), (2, 1)]);
    let bytes = genesis.encode().unwrap();
    for end in 0..bytes.len() {
        assert!(Genesis::decode(&bytes[..end], genesis.id()).is_err());
    }
    let mut reordered = bytes.clone();
    reordered[188..].rotate_left(TICKET_BYTES);
    let pin = crate::hash(b"dcs/work-finality/genesis/v1", &[&reordered]);
    assert_eq!(
        Genesis::decode(&reordered, pin),
        Err(Error::InvalidEncoding)
    );
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        Genesis::decode(&trailing, genesis.id()),
        Err(Error::InvalidEncoding)
    );
    let election = genesis.seed().bootstrap_election();
    let ticket = &genesis.bootstrap_tickets()[0];
    let original = ticket.encode();
    for end in 0..original.len() {
        assert!(WorkTicket::decode(&election, &original[..end]).is_err());
    }
    let mut damaged = original;
    damaged[216] ^= 1;
    assert_eq!(
        WorkTicket::decode(&election, &damaged),
        Err(Error::InvalidSignature)
    );
    let mut wrong_profile = original;
    wrong_profile[8] ^= 1;
    assert_eq!(
        WorkTicket::decode(&election, &wrong_profile),
        Err(Error::WrongDomain)
    );
    let expected = context(genesis.initial_set(), 0, Step::Prevote, None);
    let original = SignedVote::sign(expected, &key(1)).unwrap().encode();
    for end in 0..original.len() {
        assert!(
            SignedVote::decode_and_verify(genesis.initial_set(), &expected, &original[..end])
                .is_err()
        );
    }
    let mut last_signature = original;
    last_signature[VOTE_BYTES - 1] ^= 1;
    assert_eq!(
        SignedVote::decode_and_verify(genesis.initial_set(), &expected, &last_signature),
        Err(Error::InvalidSignature)
    );
    let mut invalid_step = original;
    invalid_step[160] = 0;
    assert_eq!(
        SignedVote::decode_and_verify(genesis.initial_set(), &expected, &invalid_step),
        Err(Error::InvalidEncoding)
    );
    let mut nil = original;
    nil[162] = 1;
    assert_eq!(
        SignedVote::decode_and_verify(genesis.initial_set(), &expected, &nil),
        Err(Error::InvalidEncoding)
    );
}

#[test]
fn explicit_configuration_bounds_reject_empty_oversized_and_overpopulated_elections() {
    assert_eq!(Limits::new(0, 1), Err(Error::InvalidConfig));
    assert_eq!(Limits::new(4097, 1), Err(Error::InvalidConfig));
    assert_eq!(Limits::new(2, 3), Err(Error::InvalidConfig));
    assert_eq!(
        NetworkSeed::new([0; 32], [0; 32], [0; 32], Limits::new(1, 1).unwrap()),
        Err(Error::InvalidConfig)
    );
    let config = seed(17, 2, 1);
    let election = config.bootstrap_election();
    assert_eq!(
        Genesis::from_bootstrap(config.clone(), vec![]),
        Err(Error::ResourceLimit)
    );
    assert_eq!(
        Genesis::from_bootstrap(config.clone(), tickets(&election, 1, 3)),
        Err(Error::ResourceLimit)
    );
    let mut two_keys = tickets(&election, 1, 1);
    two_keys.extend(tickets(&election, 2, 1));
    assert_eq!(
        Genesis::from_bootstrap(config, two_keys),
        Err(Error::ResourceLimit)
    );
}

#[test]
fn the_largest_ticket_election_is_preserved_in_full_and_the_next_ticket_is_rejected() {
    // The easiest explicit target makes this boundary fixture deterministic;
    // it is not a suggested operating difficulty or availability configuration.
    let config = NetworkSeed::new(
        [18; 32],
        [7; 32],
        [0xff; 32],
        Limits::new(4096, 4096).unwrap(),
    )
    .unwrap();
    let election = config.bootstrap_election();
    let signer = key(1);
    let claims: Vec<_> = (0..4096)
        .map(|nonce| WorkTicket::sign(&election, &signer, nonce).unwrap())
        .collect();
    let mut oversized = claims.clone();
    oversized.push(WorkTicket::sign(&election, &signer, 4096).unwrap());
    assert_eq!(
        Genesis::from_bootstrap(config.clone(), oversized),
        Err(Error::ResourceLimit)
    );
    let genesis = Genesis::from_bootstrap(config, claims).unwrap();
    let bytes = genesis.encode().unwrap();
    assert_eq!(bytes.len(), 188 + 4096 * 217);
    assert_eq!(genesis.bootstrap_tickets().len(), 4096);
    assert_eq!(genesis.initial_set().total_work_units(), 4096);
    let decoded = Genesis::decode(&bytes, genesis.id()).unwrap();
    assert_eq!(decoded.initial_set(), genesis.initial_set());
}
