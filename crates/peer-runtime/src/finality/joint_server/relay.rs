//! Joint-only bounded transport scheduling. No signer, proof gate, ledger or
//! accepted result is created here; every pass invokes the original synchronize.
use super::{Service, close_sockets, synchronize};
use peer_transport::Cancellation;
use std::{
    io,
    net::TcpStream,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

const MAX_RELAY_WORKERS: usize = 3;

/// A disjoint stride of the immutable, already bounded neighbor list. Rotate
/// the first endpoint after every pass; no endpoint is duplicated or forgotten.
struct Lane {
    index: usize,
    stride: usize,
    len: usize,
    first: usize,
}
impl Lane {
    fn new(index: usize, workers: usize, peers: usize) -> io::Result<Self> {
        if peers == 0
            || peers > super::MAX_PEERS
            || workers == 0
            || workers > MAX_RELAY_WORKERS
            || workers > peers
            || index >= workers
        {
            return Err(super::invalid());
        }
        Ok(Self {
            index,
            stride: workers,
            len: (peers - 1 - index) / workers + 1,
            first: 0,
        })
    }
    fn endpoints(&self) -> impl ExactSizeIterator<Item = usize> + '_ {
        (0..self.len).map(|offset| self.index + ((self.first + offset) % self.len) * self.stride)
    }
    fn rotate(&mut self) {
        self.first = (self.first + 1) % self.len;
    }
}

/// Own all relay JoinHandles from the FIRST successful spawn. In particular,
/// a later spawn error drops this guard and joins every already-started worker.
pub(super) struct Workers {
    joins: Vec<JoinHandle<()>>,
    lifecycle: Lifecycle,
}
#[derive(Clone)]
struct Lifecycle {
    stop: Arc<AtomicBool>,
    cancellation: Cancellation,
    sockets: Arc<Mutex<Vec<Arc<TcpStream>>>>,
}
// An unexpected worker exit must not leave a silently degraded relay lane.
// The listener observes this SAME stop flag and performs its existing cleanup;
// no worker owns or releases the actual actor/proof gate itself.
struct StopOnExit(Arc<AtomicBool>);
impl Drop for StopOnExit {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}
impl Workers {
    pub(super) fn spawn(
        service: Service,
        sockets: Arc<Mutex<Vec<Arc<TcpStream>>>>,
    ) -> io::Result<Self> {
        let peers = service.neighbors.len();
        let lifecycle = Lifecycle {
            stop: service.handle.stop.clone(),
            cancellation: service.cancellation.clone(),
            sockets,
        };
        Self::spawn_lanes(peers, lifecycle, move |index| {
            let client = service
                .application
                .client(service.connector.clone(), service.neighbors[index].clone())
                .with_cancellation(service.cancellation.clone());
            // One SAME control reservation spans this active synchronization.
            // This closure is only transport work, never an accepting verifier.
            let _ = synchronize(
                &client,
                &service.application,
                &service.handle,
                &service.bodies,
                &service.blobs,
            );
        })
    }
    // Private thread scheduling boundary shared with owning lifecycle tests.
    // It never receives a proof, signer, verified flag or cryptographic factory.
    fn spawn_lanes<F>(peers: usize, lifecycle: Lifecycle, visit: F) -> io::Result<Self>
    where
        F: Fn(usize) + Send + Sync + 'static,
    {
        if peers > super::MAX_PEERS {
            return Err(super::invalid());
        }
        let count = peers.min(MAX_RELAY_WORKERS);
        let mut owned = Self {
            joins: Vec::with_capacity(count),
            lifecycle,
        };
        let visit = Arc::new(visit);
        for index in 0..count {
            let lane = Lane::new(index, count, peers)?;
            let shared = Arc::clone(&visit);
            let stop = owned.lifecycle.stop.clone();
            owned.joins.push(
                thread::Builder::new()
                    .name(format!("dcs-joint-finality-relay-{index}"))
                    .spawn(move || {
                        let _stop_on_exit = StopOnExit(stop.clone());
                        run_lane(&stop, lane, &*shared);
                    })?,
            );
        }
        Ok(owned)
    }
    pub(super) fn shutdown_and_join(&mut self) -> io::Result<()> {
        self.lifecycle.stop.store(true, Ordering::Release);
        self.lifecycle.cancellation.cancel();
        close_sockets(&self.lifecycle.sockets);
        for join in &self.joins {
            join.thread().unpark();
        }
        // Never return early after one panic: every actual worker is joined.
        let mut panicked = false;
        for join in self.joins.drain(..) {
            panicked |= join.join().is_err();
        }
        if panicked {
            Err(io::Error::other("Joint relay worker panicked"))
        } else {
            Ok(())
        }
    }
}
impl Drop for Workers {
    fn drop(&mut self) {
        let _ = self.shutdown_and_join();
    }
}

fn run_lane(stop: &AtomicBool, mut lane: Lane, visit: &impl Fn(usize)) {
    while !stop.load(Ordering::Acquire) {
        for index in lane.endpoints() {
            if stop.load(Ordering::Acquire) {
                break;
            }
            visit(index);
        }
        lane.rotate();
        if !stop.load(Ordering::Acquire) {
            thread::park_timeout(Duration::from_millis(100));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Read,
        net::TcpListener,
        sync::{atomic::AtomicUsize, mpsc},
    };

    const WAIT: Duration = Duration::from_secs(10);

    fn lifecycle() -> Lifecycle {
        Lifecycle {
            stop: Arc::new(AtomicBool::new(false)),
            cancellation: Cancellation::default(),
            sockets: Arc::new(Mutex::new(Vec::new())),
        }
    }

    #[test]
    fn balanced_rotating_lanes_cover_every_neighbor_once_without_duplicates() {
        assert!(Lane::new(0, 0, 1).is_err());
        assert!(Lane::new(0, 1, 0).is_err());
        assert!(Lane::new(0, 4, 16).is_err());
        assert!(Lane::new(0, 3, super::super::MAX_PEERS + 1).is_err());
        for peers in 1..=super::super::MAX_PEERS {
            let count = peers.min(MAX_RELAY_WORKERS);
            let mut lanes: Vec<_> = (0..count)
                .map(|i| Lane::new(i, count, peers).unwrap())
                .collect();
            let lengths: Vec<_> = lanes.iter().map(|lane| lane.len).collect();
            assert!(*lengths.iter().max().unwrap() - *lengths.iter().min().unwrap() <= 1);
            let mut first_seen = vec![Vec::new(); count];
            for round in 0..peers {
                let mut all = Vec::new();
                for (index, lane) in lanes.iter_mut().enumerate() {
                    let pass: Vec<_> = lane.endpoints().collect();
                    if round < lane.len {
                        first_seen[index].push(pass[0]);
                    }
                    all.extend(pass);
                    lane.rotate();
                }
                all.sort_unstable();
                assert_eq!(all, (0..peers).collect::<Vec<_>>());
            }
            for (index, seen) in first_seen.iter_mut().enumerate() {
                seen.sort_unstable();
                assert_eq!(*seen, (index..peers).step_by(count).collect::<Vec<_>>());
            }
        }
    }

    #[test]
    fn blocked_first_lane_leaves_two_other_actual_workers_independent() {
        // Thread/channel scheduling only, NOT a verifier, signer or SQL result.
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let occupied = Arc::new(AtomicUsize::new(0));
        let first: Arc<[AtomicBool; 3]> = Arc::new(std::array::from_fn(|_| AtomicBool::new(false)));
        let (entered_tx, entered) = mpsc::channel();
        let (done_tx, done) = mpsc::channel();
        let mut release = Vec::new();
        let mut waits = Vec::new();
        for _ in 0..3 {
            let (go, wait) = mpsc::channel();
            release.push(go);
            waits.push(Mutex::new(wait));
        }
        let mut group = Workers::spawn_lanes(3, lifecycle(), {
            let active = active.clone();
            let peak = peak.clone();
            let occupied = occupied.clone();
            move |peer| {
                let mask = 1usize << peer;
                assert_eq!(occupied.fetch_or(mask, Ordering::AcqRel) & mask, 0);
                if first[peer].swap(true, Ordering::AcqRel) {
                    occupied.fetch_and(!mask, Ordering::AcqRel);
                    return; // later normal passes are outside this first-visit observation
                }
                let now = active.fetch_add(1, Ordering::AcqRel) + 1;
                peak.fetch_max(now, Ordering::AcqRel);
                entered_tx.send(peer).unwrap();
                waits[peer].lock().unwrap().recv_timeout(WAIT).unwrap();
                occupied.fetch_and(!mask, Ordering::AcqRel);
                active.fetch_sub(1, Ordering::AcqRel);
                done_tx.send(peer).unwrap();
            }
        })
        .unwrap();
        let mut starts: Vec<_> = (0..3)
            .map(|_| entered.recv_timeout(WAIT).unwrap())
            .collect();
        starts.sort_unstable();
        assert_eq!(starts, [0, 1, 2]);
        assert_eq!(active.load(Ordering::Acquire), 3);
        release[1].send(()).unwrap();
        release[2].send(()).unwrap();
        let mut completed = [
            done.recv_timeout(WAIT).unwrap(),
            done.recv_timeout(WAIT).unwrap(),
        ];
        completed.sort_unstable();
        assert_eq!(completed, [1, 2]);
        assert_eq!(active.load(Ordering::Acquire), 1);
        assert!(matches!(done.try_recv(), Err(mpsc::TryRecvError::Empty)));
        release[0].send(()).unwrap();
        assert_eq!(done.recv_timeout(WAIT).unwrap(), 0);
        group.shutdown_and_join().unwrap();
        assert_eq!(peak.load(Ordering::Acquire), MAX_RELAY_WORKERS);
        assert_eq!(occupied.load(Ordering::Acquire), 0);
        assert_eq!(active.load(Ordering::Acquire), 0);
    }

    #[test]
    fn early_startup_error_cancels_and_joins_every_already_started_worker() {
        fn incomplete_start(life: Lifecycle, done: mpsc::Sender<usize>) -> io::Result<()> {
            let (ready_tx, ready) = mpsc::channel();
            let stop = life.stop.clone();
            let cancellation = life.cancellation.clone();
            let _group = Workers::spawn_lanes(2, life, move |index| {
                ready_tx.send(()).unwrap();
                while !stop.load(Ordering::Acquire) || !cancellation.is_cancelled() {
                    thread::park_timeout(WAIT);
                }
                assert!(cancellation.is_cancelled());
                done.send(index).unwrap();
            })?;
            ready.recv_timeout(WAIT).unwrap();
            ready.recv_timeout(WAIT).unwrap();
            // Exercise the SAME owning guard Drop as Builder::spawn's ? error.
            // No injectable production thread factory or fake signer exists.
            Err(io::Error::other(
                "PUBLIC test: startup stopped after two actual threads",
            ))
        }
        let life = lifecycle();
        let (done_tx, done) = mpsc::channel();
        assert!(incomplete_start(life.clone(), done_tx).is_err());
        assert!(life.stop.load(Ordering::Acquire));
        assert!(life.cancellation.is_cancelled());
        let mut joined = [done.try_recv().unwrap(), done.try_recv().unwrap()];
        joined.sort_unstable();
        assert_eq!(joined, [0, 1]);
    }

    #[test]
    fn dropping_workers_shuts_down_the_registered_socket_and_joins_its_peer_reader() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let reader = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (registered, _) = listener.accept().unwrap();
        reader.set_read_timeout(Some(WAIT)).unwrap();
        let life = lifecycle();
        life.sockets
            .lock()
            .unwrap()
            .push(Arc::new(registered.try_clone().unwrap()));
        let cancellation = life.cancellation.clone();
        let reader = Mutex::new(reader);
        let (ready_tx, ready) = mpsc::channel();
        let (done_tx, done) = mpsc::channel();
        let group = Workers::spawn_lanes(1, life, move |_| {
            ready_tx.send(()).unwrap();
            let result = reader.lock().unwrap().read(&mut [0; 1]);
            assert!(
                matches!(&result, Ok(0)),
                "Expected actual peer EOF: {result:?}"
            );
            assert!(cancellation.is_cancelled());
            done_tx.send(()).unwrap();
        })
        .unwrap();
        ready.recv_timeout(WAIT).unwrap();
        drop(group);
        // Observe the actual FIN on the opposite endpoint; the registered
        // endpoint remains owned here, so dropping it cannot supply this EOF.
        // This does not assert interruption of an already pending local recv.
        // Drop returned only after the actual peer reader finished; no timeout
        // or detached worker may masquerade as successful shutdown.
        done.try_recv().unwrap();
    }

    #[test]
    fn unexpected_worker_panic_stops_the_host_and_all_other_workers_are_joined() {
        let life = lifecycle();
        let stop = life.stop.clone();
        let cancellation = life.cancellation.clone();
        let (ready_tx, ready) = mpsc::channel();
        let (panic_tx, panic_rx) = mpsc::channel();
        let panic_rx = Mutex::new(panic_rx);
        let (done_tx, done) = mpsc::channel();
        let mut group = Workers::spawn_lanes(2, life.clone(), move |index| {
            ready_tx.send(index).unwrap();
            if index == 0 {
                panic_rx.lock().unwrap().recv_timeout(WAIT).unwrap();
                panic!("PUBLIC test: unexpected relay worker panic");
            }
            while !stop.load(Ordering::Acquire) || !cancellation.is_cancelled() {
                thread::park_timeout(WAIT);
            }
            done_tx.send(index).unwrap();
        })
        .unwrap();
        let mut started = [
            ready.recv_timeout(WAIT).unwrap(),
            ready.recv_timeout(WAIT).unwrap(),
        ];
        started.sort_unstable();
        assert_eq!(started, [0, 1]);
        panic_tx.send(()).unwrap();
        let end = std::time::Instant::now() + WAIT;
        while !group.joins[0].is_finished() {
            assert!(
                std::time::Instant::now() < end,
                "actual panicking worker did not finish"
            );
            thread::yield_now();
        }
        // This assertion precedes the parent's shutdown call: worker exit,
        // not that later call, must notify the listening host to stop.
        assert!(life.stop.load(Ordering::Acquire));
        assert!(group.shutdown_and_join().is_err());
        assert!(life.cancellation.is_cancelled());
        assert!(group.joins.is_empty());
        assert_eq!(done.try_recv().unwrap(), 1);
    }
}
