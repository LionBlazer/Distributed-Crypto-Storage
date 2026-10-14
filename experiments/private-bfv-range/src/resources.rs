//! Process-local Windows sampling. The monitor never receives keys or row data.
use serde::Serialize;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};
#[derive(Clone, Serialize)]
pub struct Sample {
    pub working_set_bytes: usize,
    pub native_peak_working_set_bytes: usize,
    pub private_commit_bytes: usize,
    pub native_peak_private_commit_bytes: usize,
    pub threads: usize,
}
#[cfg(windows)]
pub fn sample() -> Sample {
    #[repr(C)]
    struct Counters {
        cb: u32,
        faults: u32,
        peak_working: usize,
        working: usize,
        quota_peak_paged: usize,
        quota_paged: usize,
        quota_peak_nonpaged: usize,
        quota_nonpaged: usize,
        pagefile: usize,
        peak_pagefile: usize,
        private_usage: usize,
    }
    #[repr(C)]
    struct ThreadEntry {
        size: u32,
        usage: u32,
        id: u32,
        owner: u32,
        priority: i32,
        priority_delta: i32,
        flags: u32,
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> *mut std::ffi::c_void;
        fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> *mut std::ffi::c_void;
        fn Thread32First(snapshot: *mut std::ffi::c_void, entry: *mut ThreadEntry) -> i32;
        fn Thread32Next(snapshot: *mut std::ffi::c_void, entry: *mut ThreadEntry) -> i32;
        fn CloseHandle(handle: *mut std::ffi::c_void) -> i32;
    }
    #[link(name = "psapi")]
    unsafe extern "system" {
        fn GetProcessMemoryInfo(
            process: *mut std::ffi::c_void,
            counters: *mut Counters,
            size: u32,
        ) -> i32;
    }
    let mut c = Counters {
        cb: std::mem::size_of::<Counters>() as u32,
        faults: 0,
        peak_working: 0,
        working: 0,
        quota_peak_paged: 0,
        quota_paged: 0,
        quota_peak_nonpaged: 0,
        quota_nonpaged: 0,
        pagefile: 0,
        peak_pagefile: 0,
        private_usage: 0,
    };
    let counter_bytes = c.cb;
    assert_ne!(
        unsafe { GetProcessMemoryInfo(GetCurrentProcess(), &mut c, counter_bytes) },
        0
    );
    let mut threads = 0;
    let mut e = ThreadEntry {
        size: std::mem::size_of::<ThreadEntry>() as u32,
        usage: 0,
        id: 0,
        owner: 0,
        priority: 0,
        priority_delta: 0,
        flags: 0,
    };
    let snapshot = unsafe { CreateToolhelp32Snapshot(4, 0) }; // TH32CS_SNAPTHREAD.
    if snapshot as isize != -1 {
        let mut present = unsafe { Thread32First(snapshot, &mut e) };
        while present != 0 {
            if e.owner == std::process::id() {
                threads += 1;
            }
            e.size = std::mem::size_of::<ThreadEntry>() as u32;
            present = unsafe { Thread32Next(snapshot, &mut e) };
        }
        unsafe {
            CloseHandle(snapshot);
        }
    }
    Sample {
        working_set_bytes: c.working,
        native_peak_working_set_bytes: c.peak_working,
        private_commit_bytes: c.private_usage,
        native_peak_private_commit_bytes: c.peak_pagefile,
        threads,
    }
}
#[cfg(not(windows))]
pub fn sample() -> Sample {
    panic!("This bounded-memory probe currently requires the Windows process-counter adapter")
}
pub struct Monitor {
    stopped: Arc<AtomicBool>,
    max_threads: Arc<AtomicUsize>,
    handle: Option<JoinHandle<()>>,
}
impl Monitor {
    pub fn start(limit: usize) -> Self {
        let stopped = Arc::new(AtomicBool::new(false));
        let max_threads = Arc::new(AtomicUsize::new(0));
        let stop = stopped.clone();
        let max = max_threads.clone();
        let handle = thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let s = sample();
                max.fetch_max(s.threads, Ordering::Relaxed);
                if s.working_set_bytes > limit
                    || s.private_commit_bytes > limit
                    || s.native_peak_working_set_bytes > limit
                    || s.native_peak_private_commit_bytes > limit
                {
                    eprintln!(
                        "RESOURCE_LIMIT working={} commit={} limit={limit}",
                        s.working_set_bytes, s.private_commit_bytes
                    );
                    std::process::exit(3);
                }
                thread::sleep(Duration::from_millis(25));
            }
        });
        Self {
            stopped,
            max_threads,
            handle: Some(handle),
        }
    }
    pub fn maximum_sampled_threads(&self) -> usize {
        self.max_threads.load(Ordering::Relaxed)
    }
}
impl Drop for Monitor {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            handle.join().expect("Sampler panicked");
        }
    }
}
