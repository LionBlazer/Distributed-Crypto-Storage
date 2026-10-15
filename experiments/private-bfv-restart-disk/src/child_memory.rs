//! Observe child OS native peaks through process exit while its process handle remains owned.
use crate::process_protocol::{NativeMemory, ProtocolResult};
#[cfg(windows)]
pub(crate) fn sample(child: &std::process::Child) -> ProtocolResult<NativeMemory> {
    use std::os::windows::io::AsRawHandle;
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
    let size = c.cb;
    if unsafe { GetProcessMemoryInfo(child.as_raw_handle(), &mut c, size) } == 0
        || c.peak_working == 0
    {
        return Err("Child native peak counters unavailable through exit".into());
    }
    Ok(NativeMemory {
        working_set_bytes: c.working,
        private_commit_bytes: c.private_usage,
        native_peak_working_set_bytes: c.peak_working,
        native_peak_private_commit_bytes: c.peak_pagefile,
    })
}
#[cfg(not(windows))]
pub(crate) fn sample(_child: &std::process::Child) -> ProtocolResult<NativeMemory> {
    Err("This native-accounted process probe requires Windows".into())
}
pub(crate) fn merge(left: NativeMemory, right: NativeMemory) -> NativeMemory {
    NativeMemory {
        working_set_bytes: left.working_set_bytes.max(right.working_set_bytes),
        private_commit_bytes: left.private_commit_bytes.max(right.private_commit_bytes),
        native_peak_working_set_bytes: left
            .native_peak_working_set_bytes
            .max(right.native_peak_working_set_bytes),
        native_peak_private_commit_bytes: left
            .native_peak_private_commit_bytes
            .max(right.native_peak_private_commit_bytes),
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    #[test]
    fn held_process_handle_retains_nonzero_os_peaks_after_actual_exit() {
        use std::os::windows::process::CommandExt;
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--list")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .creation_flags(0x0800_0000)
            .spawn()
            .unwrap();
        assert!(child.wait().unwrap().success());
        let observed =
            sample(&child).expect("Post-exit native counters are required, never inferred");
        assert!(observed.native_peak_working_set_bytes > 0);
        assert!(observed.native_peak_private_commit_bytes > 0);
    }
}
