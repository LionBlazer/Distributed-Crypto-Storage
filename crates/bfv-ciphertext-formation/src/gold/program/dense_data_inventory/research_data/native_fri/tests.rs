//! Exact DATA tape ownership, retries and raw native duplicate indices.
use super::super::research_ro::Tape;
use super::*;
use rand_public_pp::SeedableRng;

fn literal_tape() -> Tape {
    let mut tape = Tape::new();
    for counter in 0..277u64 {
        let candidate = match counter {
            15 => 2,
            16 => 1,
            17..=19 => 0,
            20..=24 => 3 * (counter - 19) + 1,
            85..=276 => {
                let query = counter - 85;
                if query == 191 {
                    17
                } else {
                    (257 * query + 17) & 32767
                }
            }
            _ => 7 * counter + 11,
        };
        let mut digest = [counter as u8; 64];
        digest[..8].copy_from_slice(&candidate.to_le_bytes());
        tape.insert((counter, 0), digest);
    }
    let first = tape.remove(&(0, 0)).unwrap();
    tape.insert((0, 0), [0xff; 64]);
    tape.insert((0, 1), first);
    tape
}

#[test]
fn exact_data_tape_retains_full_retries_and_duplicates_and_rejects_gaps_or_unused_raw_cells() {
    let tape = literal_tape();
    let plan = TapePlan::checked(tape.clone()).unwrap();
    assert_eq!(plan.accepted().len(), 277);
    assert_eq!(plan.tape.len(), 278);
    assert_eq!(plan.indices().len(), 192);
    assert_eq!(plan.positions().len(), 191);
    assert_eq!(plan.indices()[0], plan.indices()[191]);
    assert_eq!(plan.row_for_query[0], plan.row_for_query[191]);
    assert_eq!(plan.accepted()[0], F::from_u32(11));
    let mut missing = tape.clone();
    missing.remove(&(0, 1));
    assert!(matches!(TapePlan::checked(missing), Err("DATA-tape-gap")));
    let mut extra = tape.clone();
    extra.insert((277, 0), [0; 64]);
    assert!(matches!(
        TapePlan::checked(extra),
        Err("DATA-tape-unused-raw")
    ));
    let mut early_accepted = tape;
    early_accepted.insert((0, 0), [0; 64]);
    assert!(matches!(
        TapePlan::checked(early_accepted),
        Err("DATA-tape-unused-raw")
    ));
    assert!(matches!(
        TapePlan::checked(Tape::new()),
        Err("DATA-tape-raw-limit")
    ));
    let sampled = TapePlan::sample(&mut StdRng::from_seed([0xc0; 32])).unwrap();
    assert_eq!(sampled.accepted().len(), 277);
    assert!(sampled.tape.len() >= 277);
}
