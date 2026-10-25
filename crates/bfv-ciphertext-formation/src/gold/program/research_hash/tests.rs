//! Raw-key ownership regressions, not a complete mixed Query/DATA proof.
use super::ro::{Leaf, Node, Programmer, ResearchChallenger, Tape, Walks, leaf_input};
use bfv_hiding_stark::Val;
use p3_challenger::{CanObserve, CanSample};
use p3_field::PrimeCharacteristicRing;
use p3_symmetric::{CryptographicHasher, MerkleCap, PseudoCompressionFunction};
use std::panic::{AssertUnwindSafe, catch_unwind};

#[test]
fn independent_family_handles_share_exact_leaf_and_node_raw_keys_without_overwrite() {
    let programmer = Programmer::regression([0x84; 32]);
    let query_side = programmer.oracle();
    let data_side = programmer.oracle();
    let values = [Val::from_u32(17), Val::from_u32(19), Val::from_u32(23)];
    let raw = leaf_input(values);
    let first = Leaf(query_side.clone()).hash_iter(values);
    assert_eq!(first, data_side.h256(raw.clone()));
    assert_eq!(first, Leaf(data_side.clone()).hash_iter(values));
    let mut incompatible = first;
    incompatible[31] ^= 1;
    assert!(programmer.plant256(raw.clone(), incompatible).is_err());
    assert_eq!(query_side.h256(raw), first);
    let children = [first, [0x85; 32]];
    let node = Node(query_side.clone()).compress(children);
    let mut raw_node = bfv_hiding_stark::hash::NODE_DOMAIN.to_vec();
    raw_node.extend(children[0]);
    raw_node.extend(children[1]);
    assert_eq!(node, data_side.h256(raw_node));
    assert_eq!(node, Node(data_side).compress(children));
}

fn observe_statement(challenger: &mut ResearchChallenger) {
    challenger.observe(Val::from_u32(31));
    challenger.observe(MerkleCap::<Val, [u8; 32]>::new(vec![[0x86; 32]]));
}

#[test]
fn a_shared_prefix_tail_conflict_preserves_the_complete_old_raw_walk() {
    let programmer = Programmer::regression([0x87; 32]);
    let query_walks = Walks::default();
    let data_walks = Walks::default();
    let mut query_side = ResearchChallenger::receiver(programmer.oracle(), query_walks.clone());
    let mut data_side = ResearchChallenger::receiver(programmer.oracle(), data_walks.clone());
    observe_statement(&mut query_side);
    observe_statement(&mut data_side);
    let first: Val = query_side.sample();
    let second: Val = data_side.sample();
    assert_eq!(first, second);
    assert_eq!(query_walks.with_draws(), data_walks.with_draws());
    let old = query_walks.with_draws().pop().unwrap();
    let mut tape: Tape = old
        .draws
        .iter()
        .map(|draw| ((draw.counter, draw.retry), draw.digest))
        .collect();
    let accepted = old.draws.last().unwrap();
    let changed = tape.get_mut(&(accepted.counter, accepted.retry)).unwrap();
    changed[63] ^= 1;
    assert_eq!(&changed[..8], &accepted.digest[..8]);
    assert_ne!(changed, &accepted.digest);
    let mut planter = ResearchChallenger::planter(programmer.clone(), tape, Walks::default());
    observe_statement(&mut planter);
    let conflict = catch_unwind(AssertUnwindSafe(|| CanSample::<Val>::sample(&mut planter)))
        .expect_err("same-prefix different full digest must conflict");
    let message = conflict
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| conflict.downcast_ref::<&str>().copied());
    assert_eq!(message, Some("programming conflict: ()"));
    // A new receiver uses the SAME original dictionary, with no reset or retry
    // of the failed producer. Only the immutable old transcript is replayed.
    let replay_walks = Walks::default();
    let mut replay = ResearchChallenger::receiver(programmer.oracle(), replay_walks.clone());
    observe_statement(&mut replay);
    let replayed: Val = replay.sample();
    assert_eq!(replayed, first);
    assert_eq!(replay_walks.with_draws(), [old]);
}
