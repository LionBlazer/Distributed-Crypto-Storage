//! Test-only native Windows observation copied from the reviewed process sampler.
#[derive(Clone, Copy, Debug)]
pub struct MemorySample {
    pub working_set_bytes: usize,
    pub native_peak_working_set_bytes: usize,
    pub private_commit_bytes: usize,
    pub native_peak_private_commit_bytes: usize,
}
#[cfg(windows)]
pub fn memory_sample() -> MemorySample {
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
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> *mut std::ffi::c_void;
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
    let bytes = c.cb;
    assert_ne!(
        unsafe { GetProcessMemoryInfo(GetCurrentProcess(), &mut c, bytes) },
        0
    );
    MemorySample {
        working_set_bytes: c.working,
        native_peak_working_set_bytes: c.peak_working,
        private_commit_bytes: c.private_usage,
        native_peak_private_commit_bytes: c.peak_pagefile,
    }
}

pub fn check(phase: &str) {
    let sample = memory_sample();
    assert!(sample.working_set_bytes < 2_000_000_000);
    assert!(sample.private_commit_bytes < 2_000_000_000);
    assert!(sample.native_peak_working_set_bytes < 2_000_000_000);
    assert!(sample.native_peak_private_commit_bytes < 2_000_000_000);
    println!(
        "RECOVERY_NATIVE phase={phase} working={} private={} native_peak_working={} native_peak_private={}",
        sample.working_set_bytes,
        sample.private_commit_bytes,
        sample.native_peak_working_set_bytes,
        sample.native_peak_private_commit_bytes
    );
}
