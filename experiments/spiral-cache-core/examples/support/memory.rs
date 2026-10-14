//! Windows-only, process-local experiment guard. No library unsafe code is added.
use serde::Serialize;

pub const RSS_LIMIT: u64 = 2_000_000_000;
pub const PRIVATE_LIMIT: u64 = 1_850_000_000;
#[derive(Clone, Copy, Serialize)]
pub struct Memory {
    pub working_set_bytes: u64,
    pub peak_working_set_bytes: u64,
    pub private_commit_bytes: u64,
    pub peak_commit_bytes: u64,
}
#[cfg(windows)]
fn sample() -> Result<Memory, Box<dyn std::error::Error>> {
    use std::ffi::c_void;
    #[repr(C)]
    #[derive(Default)]
    struct Counters {
        cb: u32,
        faults: u32,
        peak_working_set: usize,
        working_set: usize,
        peak_paged: usize,
        paged: usize,
        peak_nonpaged: usize,
        nonpaged: usize,
        pagefile: usize,
        peak_pagefile: usize,
        private: usize,
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> *mut c_void;
    }
    #[link(name = "psapi")]
    unsafe extern "system" {
        fn GetProcessMemoryInfo(process: *mut c_void, counters: *mut Counters, size: u32) -> i32;
    }
    let size = std::mem::size_of::<Counters>() as u32;
    let mut counters = Counters {
        cb: size,
        ..Counters::default()
    };
    // SAFETY: pseudo-handle refers to this process, the initialized writable
    // PROCESS_MEMORY_COUNTERS_EX layout and byte size match the Windows API.
    let success = unsafe { GetProcessMemoryInfo(GetCurrentProcess(), &mut counters, size) };
    if success == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(Memory {
        working_set_bytes: counters.working_set as u64,
        peak_working_set_bytes: counters.peak_working_set as u64,
        private_commit_bytes: counters.private as u64,
        peak_commit_bytes: counters.peak_pagefile as u64,
    })
}
#[cfg(not(windows))]
fn sample() -> Result<Memory, Box<dyn std::error::Error>> {
    Err("This bounded-memory experiment requires Windows native memory counters".into())
}
pub fn guard(reserve: u64) -> Result<Memory, Box<dyn std::error::Error>> {
    let current = sample()?;
    if current.working_set_bytes.saturating_add(reserve) > RSS_LIMIT
        || current.peak_working_set_bytes > RSS_LIMIT
        || current.private_commit_bytes.saturating_add(reserve) > PRIVATE_LIMIT
        || current.peak_commit_bytes > PRIVATE_LIMIT
    {
        return Err("Process memory guard rejected the next bounded experiment allocation".into());
    }
    Ok(current)
}
