//! Local process CPU allocation; no protocol, proof or security profile defaults.
pub(super) fn cpu_workers() -> usize {
    let available = std::thread::available_parallelism().map_or(1, usize::from);
    let requested = std::env::var("RAYON_NUM_THREADS").ok();
    proof_acceleration::worker_budget(available, requested.as_deref())
}
