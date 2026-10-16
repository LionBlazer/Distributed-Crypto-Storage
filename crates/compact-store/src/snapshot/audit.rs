//! Optional bounded leaf hashing after canonical framing/revision preflight.
use super::{leaf, packets};
use crate::Layout;
use std::{
    io,
    sync::atomic::{AtomicBool, Ordering},
    thread,
};

/// Caller-selected upper bound for one complete canonical image audit.
/// `Two` permits one scoped helper; small images, contention or a failed spawn
/// still perform the complete audit serially. This does not select an executor,
/// change decode limits or bound all CPU workers in the hosting process.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AuditWorkers {
    #[default]
    One,
    Two,
}

const MIN_PARALLEL_IMAGE_BYTES: usize = 4 * 1024 * 1024;
const HELPER_STACK_BYTES: usize = 512 * 1024;
// Shared by all concurrent audits in this linked library image, including callers
// outside a store mutex. This holds no ciphertext, validation result or cache.
static HELPER_BUSY: AtomicBool = AtomicBool::new(false);

struct HelperPermit<'a>(&'a AtomicBool);
impl<'a> HelperPermit<'a> {
    fn acquire(busy: &'a AtomicBool) -> Option<Self> {
        busy.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| Self(busy))
    }
}
impl Drop for HelperPermit<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

enum Spawn {
    Os,
    #[cfg(test)]
    Fail,
    #[cfg(test)]
    ObserveScopeExit(std::sync::mpsc::SyncSender<()>),
}
impl Spawn {
    fn start<'scope, 'env: 'scope, F>(
        self,
        scope: &'scope thread::Scope<'scope, 'env>,
        work: F,
    ) -> io::Result<thread::ScopedJoinHandle<'scope, ()>>
    where
        F: FnOnce() + Send + 'scope,
    {
        #[cfg(test)]
        if matches!(self, Self::Fail) {
            return Err(io::Error::other("injected audit helper spawn failure"));
        }
        thread::Builder::new()
            .name("dcs-custody-audit".into())
            .stack_size(HELPER_STACK_BYTES)
            .spawn_scoped(scope, work)
    }
    #[cfg(test)]
    fn scope_exit(&self) -> ScopeExit {
        ScopeExit(match self {
            Self::ObserveScopeExit(sender) => Some(sender.clone()),
            _ => None,
        })
    }
}

// Test-only lifecycle observation; even this mode uses the actual OS spawn and
// genuine hashing. Declared first in the scope body, it signals last on unwind.
#[cfg(test)]
struct ScopeExit(Option<std::sync::mpsc::SyncSender<()>>);
#[cfg(test)]
impl Drop for ScopeExit {
    fn drop(&mut self) {
        if let Some(sender) = &self.0 {
            let _ = sender.send(());
        }
    }
}

// A failure to acquire or spawn runs neither closure; the caller must fill ALL
// leaves serially. A panic never returns success: join/resume_unwind and scope
// cleanup finish the helper before the shared permit is released.
fn run_halves(
    busy: &AtomicBool,
    spawn: Spawn,
    left: impl FnOnce(),
    right: impl FnOnce() + Send,
) -> bool {
    let Some(_permit) = HelperPermit::acquire(busy) else {
        return false;
    };
    thread::scope(|scope| {
        #[cfg(test)]
        let _scope_exit = spawn.scope_exit();
        let Ok(helper) = spawn.start(scope, right) else {
            return false;
        };
        left();
        if let Err(panic) = helper.join() {
            std::panic::resume_unwind(panic);
        }
        true
    })
}

pub(super) fn leaf_hashes(bytes: &[u8], layout: Layout, workers: AuditWorkers) -> Vec<[u8; 32]> {
    leaf_hashes_with(bytes, layout, workers, &HELPER_BUSY, Spawn::Os)
}

fn leaf_hashes_with(
    bytes: &[u8],
    layout: Layout,
    workers: AuditWorkers,
    busy: &AtomicBool,
    spawn: Spawn,
) -> Vec<[u8; 32]> {
    let source = packets(bytes, layout);
    let count = source.len();
    if workers == AuditWorkers::One || bytes.len() < MIN_PARALLEL_IMAGE_BYTES || count < 2 {
        return source
            .enumerate()
            .map(|(index, packet)| leaf(index, packet))
            .collect();
    }
    // Exactly the already bounded leaf payload, with disjoint output halves.
    // No packet is copied and no per-packet task or second result vector exists.
    let mut leaves = vec![[0; 32]; count];
    let midpoint = count / 2;
    let (left, right) = leaves.split_at_mut(midpoint);
    let left_packets = source.clone().take(midpoint);
    let right_packets = source.skip(midpoint);
    if !run_halves(
        busy,
        spawn,
        || fill_leaves(left_packets, 0, left),
        || fill_leaves(right_packets, midpoint, right),
    ) {
        fill_leaves(packets(bytes, layout), 0, &mut leaves);
    }
    leaves
}

fn fill_leaves<'a>(
    source: impl ExactSizeIterator<Item = &'a [u8]>,
    first: usize,
    output: &mut [[u8; 32]],
) {
    assert_eq!(source.len(), output.len());
    for (offset, (packet, destination)) in source.zip(output).enumerate() {
        *destination = leaf(first + offset, packet);
    }
}

#[cfg(test)]
mod tests;
