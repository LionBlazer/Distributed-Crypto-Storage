#![cfg(feature = "runtime-dispatch")]

use bfv_query_proof::{BackendKind, Error, initialize_backend, prove, verify};
use proof_acceleration::abi::kernel_file_name;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

struct Installation(PathBuf);
impl Drop for Installation {
    fn drop(&mut self) {
        for kind in [BackendKind::Avx2, BackendKind::Avx512] {
            let _ = std::fs::remove_file(self.0.join(kernel_file_name(kind)));
        }
        let _ = std::fs::remove_dir(&self.0);
    }
}

#[test]
fn invalid_present_selected_kernel_keeps_the_process_fail_closed() {
    let Some(kind) = [BackendKind::Avx512, BackendKind::Avx2]
        .into_iter()
        .find(|kind| kind.is_supported())
    else {
        // A baseline-only platform has no optional SIMD library to select.
        return;
    };
    let directory = Installation(std::env::temp_dir().join(format!(
        "dcs-proof-invalid-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    )));
    std::fs::create_dir(&directory.0).unwrap();
    std::fs::write(
        directory.0.join(kernel_file_name(kind)),
        b"invalid native library",
    )
    .unwrap();

    assert_eq!(
        initialize_backend(&directory.0),
        Err(Error::BackendUnavailable)
    );

    // Failure cannot silently fall back, even after a later caller supplies a
    // directory with no optional libraries. No unchecked marker can be produced.
    assert_eq!(
        initialize_backend(&directory.0.join("absent")),
        Err(Error::BackendUnavailable)
    );
    assert!(matches!(prove(&[]), Err(Error::BackendUnavailable)));
    assert!(matches!(
        verify(&[], &[], &[]),
        Err(Error::BackendUnavailable)
    ));
}
