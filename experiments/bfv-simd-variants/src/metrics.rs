//! Process high-water resident memory, including both client and evaluator in this experiment.

#[cfg(windows)]
pub fn peak_resident_bytes() -> Option<u64> {
    use windows_sys::Win32::System::ProcessStatus::{
        GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    let size = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
    let mut counters = PROCESS_MEMORY_COUNTERS {
        cb: size,
        ..Default::default()
    };
    // SAFETY: the pseudo-handle refers to this process; the initialized writable
    // buffer has exactly the size supplied to the Windows API. No handle is owned.
    let success = unsafe { GetProcessMemoryInfo(GetCurrentProcess(), &mut counters, size) };
    (success != 0).then_some(counters.PeakWorkingSetSize as u64)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn peak_resident_bytes() -> Option<u64> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: getrusage initializes the correctly sized buffer on success.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: the call succeeded and initialized usage.
    let usage = unsafe { usage.assume_init() };
    #[cfg(target_os = "linux")]
    let scale = 1_024;
    #[cfg(target_os = "macos")]
    let scale = 1;
    Some(usage.ru_maxrss as u64 * scale)
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub fn peak_resident_bytes() -> Option<u64> {
    None
}

#[cfg(windows)]
pub fn native_memory() -> serde_json::Value {
    use windows_sys::Win32::System::ProcessStatus::{
        GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    let size = std::mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32;
    let mut counters = PROCESS_MEMORY_COUNTERS_EX {
        cb: size,
        ..Default::default()
    };
    // SAFETY: EX extends the base structure; the API receives the full initialized
    // writable EX buffer and its actual byte size, for this process's pseudo-handle.
    let success = unsafe {
        GetProcessMemoryInfo(
            GetCurrentProcess(),
            (&mut counters as *mut PROCESS_MEMORY_COUNTERS_EX).cast::<PROCESS_MEMORY_COUNTERS>(),
            size,
        )
    };
    if success == 0 {
        return serde_json::Value::Null;
    }
    serde_json::json!({
        "peak_working_set_bytes": counters.PeakWorkingSetSize,
        "working_set_bytes": counters.WorkingSetSize,
        "peak_commit_bytes": counters.PeakPagefileUsage,
        "private_commit_bytes": counters.PrivateUsage,
    })
}
#[cfg(not(windows))]
pub fn native_memory() -> serde_json::Value {
    serde_json::json!({ "peak_working_set_bytes": peak_resident_bytes(),
        "peak_commit_bytes": null, "private_commit_bytes": null })
}
