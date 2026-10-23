//! ISOLATED owning-test candidate. Not imported by production or normal proof facades.
//! Lazy finite dictionary with an explicit deterministic regression RNG, NOT SHA
//! and NOT an implementation proof of an ideal random oracle or PRG assumption.
use bfv_hiding_stark::{Challenge, Val};
use p3_challenger::{CanObserve, CanSample, CanSampleBits, FieldChallenger, GrindingChallenger};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
use p3_symmetric::{CryptographicHasher, MerkleCap, PseudoCompressionFunction};
use rand_public_pp::{Rng, SeedableRng, rngs::StdRng};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

const MAX_KEY_BYTES: usize = 768 * 1024 * 1024;
const MAX_INPUT_BYTES: usize = 1024 * 1024;
const MAX_ENTRIES: usize = 1024 * 1024;
const MAX_TRACES: usize = 32;
const MAX_DRAWS: usize = 4096;
const MAX_PREFIX: usize = 1024 * 1024;

type Digest256 = [u8; 32];
type Digest512 = [u8; 64];
pub(super) type Tape = BTreeMap<(u64, u64), Digest512>;

struct State {
    h256: BTreeMap<Vec<u8>, Digest256>,
    h512: BTreeMap<Vec<u8>, Digest512>,
    rng: StdRng,
    keys: usize,
    queries256: usize,
    queries512: usize,
}

/// Explicit owner of programming rights. Never passed to native receiver code.
#[derive(Clone)]
pub(super) struct Programmer(Arc<Mutex<State>>);

/// Query-only interface used by actual MMCS and verifier challenger implementations.
#[derive(Clone)]
pub(super) struct Oracle(Arc<Mutex<State>>);

impl Programmer {
    pub(super) fn regression(seed: [u8; 32]) -> Self {
        Self(Arc::new(Mutex::new(State {
            h256: BTreeMap::new(),
            h512: BTreeMap::new(),
            rng: StdRng::from_seed(seed),
            keys: 0,
            queries256: 0,
            queries512: 0,
        })))
    }
    pub(super) fn oracle(&self) -> Oracle {
        Oracle(Arc::clone(&self.0))
    }

    /// The public simulator may plant an absent point or repeat its existing value.
    /// Conflict is a named model failure; it MUST NOT overwrite an old answer.
    pub(super) fn plant256(&self, input: Vec<u8>, output: Digest256) -> Result<(), ()> {
        let mut state = self.0.lock().unwrap();
        if let Some(old) = state.h256.get(&input) {
            return if old == &output { Ok(()) } else { Err(()) };
        }
        state.reserve(&input);
        state.h256.insert(input, output);
        Ok(())
    }
    fn plant512(&self, input: Vec<u8>, output: Digest512) -> Result<Digest512, ()> {
        let mut state = self.0.lock().unwrap();
        state.queries512 = state.queries512.checked_add(1).unwrap();
        if let Some(old) = state.h512.get(&input) {
            return if old == &output { Ok(output) } else { Err(()) };
        }
        state.reserve(&input);
        state.h512.insert(input, output);
        Ok(output)
    }
}
impl State {
    fn reserve(&mut self, input: &[u8]) {
        assert!(
            input.len() <= MAX_INPUT_BYTES,
            "research input resource cap"
        );
        self.keys = self.keys.checked_add(input.len()).unwrap();
        assert!(self.keys <= MAX_KEY_BYTES, "research dictionary byte cap");
        assert!(
            self.h256.len() + self.h512.len() < MAX_ENTRIES,
            "research entry cap"
        );
    }
}
impl Oracle {
    pub(super) fn h256(&self, input: Vec<u8>) -> Digest256 {
        let mut state = self.0.lock().unwrap();
        state.queries256 = state.queries256.checked_add(1).unwrap();
        if let Some(output) = state.h256.get(&input) {
            return *output;
        }
        state.reserve(&input);
        let mut output = [0; 32];
        state.rng.fill_bytes(&mut output);
        state.h256.insert(input, output);
        output
    }
    fn h512(&self, input: Vec<u8>) -> Digest512 {
        let mut state = self.0.lock().unwrap();
        state.queries512 = state.queries512.checked_add(1).unwrap();
        if let Some(output) = state.h512.get(&input) {
            return *output;
        }
        state.reserve(&input);
        let mut output = [0; 64];
        state.rng.fill_bytes(&mut output);
        state.h512.insert(input, output);
        output
    }
}

pub(super) fn leaf_input(values: impl IntoIterator<Item = Val>) -> Vec<u8> {
    let mut output = bfv_hiding_stark::hash::LEAF_DOMAIN.to_vec();
    let mut count = 0u64;
    for value in values {
        assert!(output.len() <= MAX_INPUT_BYTES - 16);
        output.extend(value.as_canonical_u64().to_le_bytes());
        count = count.checked_add(1).unwrap();
    }
    output.extend(count.to_le_bytes());
    output
}
#[derive(Clone)]
pub(super) struct Leaf(pub(super) Oracle);
impl CryptographicHasher<Val, Digest256> for Leaf {
    fn hash_iter<I: IntoIterator<Item = Val>>(&self, input: I) -> Digest256 {
        self.0.h256(leaf_input(input))
    }
}
#[derive(Clone)]
pub(super) struct Node(pub(super) Oracle);
impl PseudoCompressionFunction<Digest256, 2> for Node {
    fn compress(&self, children: [Digest256; 2]) -> Digest256 {
        let mut input = bfv_hiding_stark::hash::NODE_DOMAIN.to_vec();
        for child in children {
            input.extend(child);
        }
        self.0.h256(input)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Event {
    Field(u64),
    Cap(Vec<Digest256>),
    Sample { counter: u64, value: u64 },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Draw {
    pub(super) prefix_len: usize,
    pub(super) counter: u64,
    pub(super) retry: u64,
    pub(super) digest: Digest512,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Walk {
    pub(super) prefix: Vec<u8>,
    pub(super) events: Vec<Event>,
    pub(super) draws: Vec<Draw>,
}
#[derive(Clone, Default)]
pub(super) struct Walks(Arc<Mutex<Vec<Walk>>>);
impl Walks {
    fn fork(&self, walk: Walk) -> usize {
        let mut walks = self.0.lock().unwrap();
        assert!(walks.len() < MAX_TRACES);
        let index = walks.len();
        walks.push(walk);
        index
    }
    pub(super) fn with_draws(&self) -> Vec<Walk> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|walk| !walk.draws.is_empty())
            .cloned()
            .collect()
    }
}

#[derive(Clone)]
enum Access {
    Query(Oracle),
    Plant(Programmer, Arc<Tape>),
}

pub(super) struct ResearchChallenger {
    prefix: Vec<u8>,
    counter: u64,
    access: Access,
    walks: Walks,
    trace: usize,
}
impl Clone for ResearchChallenger {
    fn clone(&self) -> Self {
        let old = self.walks.0.lock().unwrap()[self.trace].clone();
        let trace = self.walks.fork(old);
        Self {
            prefix: self.prefix.clone(),
            counter: self.counter,
            access: self.access.clone(),
            walks: self.walks.clone(),
            trace,
        }
    }
}
impl ResearchChallenger {
    fn new(access: Access, walks: Walks) -> Self {
        let prefix = bfv_hiding_stark::hash::TRANSCRIPT_DOMAIN.to_vec();
        let trace = walks.fork(Walk {
            prefix: prefix.clone(),
            ..Walk::default()
        });
        Self {
            prefix,
            counter: 0,
            access,
            walks,
            trace,
        }
    }
    pub(super) fn receiver(oracle: Oracle, walks: Walks) -> Self {
        Self::new(Access::Query(oracle), walks)
    }
    pub(super) fn planter(programmer: Programmer, tape: Tape, walks: Walks) -> Self {
        Self::new(Access::Plant(programmer, Arc::new(tape)), walks)
    }
    fn absorb(&mut self, bytes: &[u8]) {
        assert!(self.prefix.len().checked_add(bytes.len()).unwrap() <= MAX_PREFIX);
        self.prefix.extend(bytes);
        self.walks.0.lock().unwrap()[self.trace]
            .prefix
            .extend(bytes);
    }
    fn event(&self, event: Event) {
        self.walks.0.lock().unwrap()[self.trace].events.push(event);
    }
    fn field(&mut self) -> Val {
        let counter = self.counter;
        let mut retry = 0u64;
        let value = loop {
            let mut input = self.prefix.clone();
            input.push(4);
            input.extend(counter.to_le_bytes());
            input.extend(retry.to_le_bytes());
            let digest = match &self.access {
                Access::Query(oracle) => oracle.h512(input),
                Access::Plant(programmer, tape) => {
                    let output = *tape
                        .get(&(counter, retry))
                        .expect("missing presampled raw digest");
                    programmer
                        .plant512(input, output)
                        .expect("programming conflict")
                }
            };
            let draw = Draw {
                prefix_len: self.prefix.len(),
                counter,
                retry,
                digest,
            };
            let mut walks = self.walks.0.lock().unwrap();
            assert!(walks[self.trace].draws.len() < MAX_DRAWS);
            walks[self.trace].draws.push(draw);
            drop(walks);
            let candidate = u64::from_le_bytes(digest[..8].try_into().unwrap());
            if candidate < Val::ORDER_U64 {
                break candidate;
            }
            retry = retry.checked_add(1).unwrap();
        };
        self.counter = self.counter.checked_add(1).unwrap();
        self.absorb(&[3]);
        self.absorb(&counter.to_le_bytes());
        self.absorb(&value.to_le_bytes());
        self.event(Event::Sample { counter, value });
        Val::from_u64(value)
    }
}
impl CanObserve<Val> for ResearchChallenger {
    fn observe(&mut self, value: Val) {
        let value = value.as_canonical_u64();
        self.absorb(&[1]);
        self.absorb(&value.to_le_bytes());
        self.event(Event::Field(value));
    }
}
impl CanObserve<&MerkleCap<Val, Digest256>> for ResearchChallenger {
    fn observe(&mut self, cap: &MerkleCap<Val, Digest256>) {
        self.absorb(&[2]);
        self.absorb(&u64::try_from(cap.num_roots()).unwrap().to_le_bytes());
        for root in cap.roots() {
            self.absorb(root);
        }
        self.event(Event::Cap(cap.roots().to_vec()));
    }
}
impl CanObserve<MerkleCap<Val, Digest256>> for ResearchChallenger {
    fn observe(&mut self, cap: MerkleCap<Val, Digest256>) {
        self.observe(&cap);
    }
}
impl CanSample<Val> for ResearchChallenger {
    fn sample(&mut self) -> Val {
        self.field()
    }
}
impl CanSample<Challenge> for ResearchChallenger {
    fn sample(&mut self) -> Challenge {
        Challenge::from_basis_coefficients_fn(|_| self.field())
    }
}
impl CanSampleBits<usize> for ResearchChallenger {
    fn sample_bits(&mut self, bits: usize) -> usize {
        assert!(bits < 64 && bits < usize::BITS as usize);
        (self.field().as_canonical_u64() & ((1u64 << bits) - 1)) as usize
    }
}
impl FieldChallenger<Val> for ResearchChallenger {}
impl GrindingChallenger for ResearchChallenger {
    type Witness = Val;
    fn grind(&mut self, bits: usize) -> Val {
        assert_eq!(bits, 0);
        Val::ZERO
    }
    fn check_witness(&mut self, bits: usize, witness: Val) -> bool {
        bits == 0 && witness == Val::ZERO
    }
}

#[test]
fn a_planted_rejected_raw_attempt_replays_in_the_query_only_challenger() {
    let programmer = Programmer::regression([0x74; 32]);
    let mut rejected = [0xa5; 64];
    rejected[..8].copy_from_slice(&u64::MAX.to_le_bytes());
    let mut accepted = [0x5a; 64];
    accepted[..8].copy_from_slice(&7u64.to_le_bytes());
    let tape = [((0, 0), rejected), ((0, 1), accepted)]
        .into_iter()
        .collect();
    let a = Walks::default();
    let b = Walks::default();
    let mut plant = ResearchChallenger::planter(programmer.clone(), tape, a.clone());
    let mut read = ResearchChallenger::receiver(programmer.oracle(), b.clone());
    let cap = MerkleCap::<Val, Digest256>::new(vec![[0x35; 32]]);
    plant.observe(&cap);
    read.observe(&cap);
    let p: Val = plant.sample();
    let r: Val = read.sample();
    assert_eq!(p, Val::from_u64(7));
    assert_eq!(p, r);
    assert_eq!(a.with_draws(), b.with_draws());
    assert!(programmer.plant512(b"existing".to_vec(), [0; 64]).is_ok());
    assert!(programmer.plant512(b"existing".to_vec(), [1; 64]).is_err());
    let leaf = leaf_input([Val::from_u64(9), Val::from_u64(10)]);
    assert!(programmer.plant256(leaf.clone(), [0x67; 32]).is_ok());
    assert_eq!(programmer.oracle().h256(leaf.clone()), [0x67; 32]);
    assert!(programmer.plant256(leaf, [0x68; 32]).is_err());
}
