//! Bounded unit-test observation of selected concrete PUBLIC SHA helpers.
//! Records their real update bytes and digest; never substitutes a hash answer.
use sha2::Digest;
use std::cell::{Cell, RefCell};

const MAX_INPUT: usize = 1024 * 1024;
const MAX_TOTAL: usize = 16 * 1024 * 1024;
const MAX_CALLS: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Algorithm {
    Sha256,
    Sha512,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Call {
    pub(super) algorithm: Algorithm,
    pub(super) input: Vec<u8>,
    pub(super) digest: Vec<u8>,
}
struct State {
    epoch: u64,
    bytes: usize,
    calls: Vec<Call>,
}
thread_local! {
    static ACTIVE: RefCell<Option<State>> = const { RefCell::new(None) };
    static EPOCH: Cell<u64> = const { Cell::new(0) };
}
struct Reset(u64);
impl Drop for Reset {
    fn drop(&mut self) {
        ACTIVE.with(|slot| {
            let mut state = slot.borrow_mut();
            assert!(state.as_ref().is_none_or(|s| s.epoch == self.0));
            *state = None;
        });
    }
}

/// Observe only helpers completed on this calling thread and inside this scope.
/// A panic discards the partial manifest. No observer follows Rayon workers.
pub(super) fn capture<T>(operation: impl FnOnce() -> T) -> (T, Vec<Call>) {
    ACTIVE.with(|slot| assert!(slot.borrow().is_none(), "nested public hash capture"));
    let epoch = EPOCH.with(|value| {
        let next = value.get().checked_add(1).unwrap();
        value.set(next);
        next
    });
    ACTIVE.with(|slot| {
        *slot.borrow_mut() = Some(State {
            epoch,
            bytes: 0,
            calls: Vec::new(),
        })
    });
    let reset = Reset(epoch);
    let value = operation();
    let state = ACTIVE.with(|slot| slot.borrow_mut().take().unwrap());
    assert_eq!(state.epoch, epoch);
    drop(reset);
    (value, state.calls)
}
fn start() -> Option<(u64, Vec<u8>)> {
    ACTIVE.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|state| (state.epoch, Vec::new()))
    })
}
fn append(trace: &mut Option<(u64, Vec<u8>)>, bytes: &[u8]) {
    if let Some((_, input)) = trace {
        assert!(input.len().checked_add(bytes.len()).unwrap() <= MAX_INPUT);
        input.extend_from_slice(bytes);
    }
}
fn finish(trace: Option<(u64, Vec<u8>)>, algorithm: Algorithm, digest: &[u8]) {
    let Some((epoch, input)) = trace else {
        return;
    };
    ACTIVE.with(|slot| {
        let mut state = slot.borrow_mut();
        let state = state.as_mut().expect("public hash capture scope ended");
        assert_eq!(state.epoch, epoch, "public hash capture scope changed");
        assert!(state.calls.len() < MAX_CALLS);
        state.bytes = state.bytes.checked_add(input.len()).unwrap();
        assert!(state.bytes <= MAX_TOTAL);
        state.calls.push(Call {
            algorithm,
            input,
            digest: digest.to_vec(),
        });
    });
}
macro_rules! observed_sha {
    ($name:ident, $native:ty, $algorithm:ident) => {
        pub(super) struct $name {
            inner: $native,
            trace: Option<(u64, Vec<u8>)>,
        }
        impl $name {
            pub(super) fn new() -> Self {
                Self {
                    inner: <$native as Digest>::new(),
                    trace: start(),
                }
            }
            pub(super) fn update(&mut self, bytes: impl AsRef<[u8]>) {
                let bytes = bytes.as_ref();
                append(&mut self.trace, bytes);
                Digest::update(&mut self.inner, bytes);
            }
            pub(super) fn finalize(self) -> sha2::digest::Output<$native> {
                let digest = Digest::finalize(self.inner);
                finish(self.trace, Algorithm::$algorithm, &digest);
                digest
            }
            pub(super) fn digest(bytes: impl AsRef<[u8]>) -> sha2::digest::Output<$native> {
                let mut hash = Self::new();
                hash.update(bytes);
                hash.finalize()
            }
        }
    };
}
observed_sha!(Sha256, sha2::Sha256, Sha256);
observed_sha!(Sha512, sha2::Sha512, Sha512);

#[test]
fn actual_sha_bytes_and_results_survive_observation_and_panic_cleanup() {
    let ((sha256, sha512), calls) = capture(|| {
        let mut incremental = Sha256::new();
        incremental.update(b"PUBLIC");
        incremental.update([0, 255]);
        (incremental.finalize(), Sha512::digest(b"public seed"))
    });
    assert_eq!(sha256, sha2::Sha256::digest(b"PUBLIC\0\xff"));
    assert_eq!(sha512, sha2::Sha512::digest(b"public seed"));
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].input, b"PUBLIC\0\xff");
    assert_eq!(calls[0].digest, sha256.to_vec());
    assert_eq!(calls[0].algorithm, Algorithm::Sha256);
    assert_eq!(calls[1].input, b"public seed");
    assert_eq!(calls[1].digest, sha512.to_vec());
    assert_eq!(calls[1].algorithm, Algorithm::Sha512);
    let panic = std::panic::catch_unwind(|| {
        capture(|| {
            let _ = Sha256::digest(b"discarded public manifest");
            panic!("public fixture interruption");
        });
    });
    assert!(panic.is_err());
    let (after, calls) = capture(|| Sha256::digest(b"after interruption"));
    assert_eq!(after, sha2::Sha256::digest(b"after interruption"));
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].input, b"after interruption");
}
