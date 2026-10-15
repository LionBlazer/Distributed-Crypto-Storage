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
