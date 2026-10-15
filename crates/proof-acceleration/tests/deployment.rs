use proof_acceleration::{Kind, abi};
use sha2::{Digest, Sha256};

#[test]
fn profile_identifier_binds_the_complete_shared_description() {
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(abi::PROFILE_DESCRIPTION)),
        abi::PROFILE_ID
    );
    assert_eq!(Kind::from_abi(3), None);
    assert_eq!(Kind::Avx512.name(), "avx512");
}

#[test]
fn c_descriptors_and_timings_have_fixed_layouts() {
    use std::mem::{align_of, offset_of, size_of};
    assert_eq!(size_of::<abi::Descriptor>(), 40);
    assert_eq!(offset_of!(abi::Descriptor, abi_version), 0);
    assert_eq!(offset_of!(abi::Descriptor, kind), 4);
    assert_eq!(offset_of!(abi::Descriptor, profile_id), 8);
    assert_eq!(size_of::<abi::Timings>(), 32);
    assert_eq!(align_of::<abi::Span>(), align_of::<usize>());
    assert_eq!(size_of::<abi::Span>(), 2 * size_of::<usize>());
    assert_eq!(size_of::<abi::Buffer>(), 3 * size_of::<usize>());
    assert_eq!(offset_of!(abi::Span, len), size_of::<usize>());
    assert_eq!(offset_of!(abi::Buffer, capacity), size_of::<usize>());
    assert_eq!(offset_of!(abi::Buffer, written), 2 * size_of::<usize>());
    assert_eq!(abi::MAX_INPUT_BYTES, 40 + 2 * 81_920 * 8);
    assert_eq!(abi::OUTPUT_BYTES, 40 + 81_920 * 8);
}

#[cfg(feature = "loader")]
mod loader {
    use super::*;
    use proof_acceleration::{Kernel, LoadError};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Installation(PathBuf);
    impl Installation {
        fn empty() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "dcs-proof-loader-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).expect("create independent test installation");
            Self(path)
        }
    }
    impl Drop for Installation {
        fn drop(&mut self) {
            // Exactly the directory this test created; no discovery or derived
            // parent traversal is used for cleanup.
            std::fs::remove_dir_all(&self.0).expect("remove test installation");
        }
    }

    #[test]
    fn missing_siblings_select_the_linked_baseline() {
        let directory = Installation::empty();
        assert!(Kernel::select(&directory.0).unwrap().is_none());
        assert!(
            Kernel::select(&directory.0.join("not-installed"))
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            Kernel::load(&directory.0, Kind::Baseline),
            Err(LoadError::MissingKernel { .. })
        ));
    }

    #[test]
    fn relative_paths_cannot_load_from_the_working_directory() {
        assert!(matches!(
            Kernel::select(Path::new(".")),
            Err(LoadError::InvalidPath { .. })
        ));
        assert!(matches!(
            Kernel::load(Path::new("kernels"), Kind::Baseline),
            Err(LoadError::InvalidPath { .. })
        ));
    }

    #[test]
    fn corrupt_supported_kernel_fails_instead_of_falling_back() {
        let directory = Installation::empty();
        // Baseline exists on every architecture, so the explicit-load branch is
        // always exercised without executing foreign test code.
        std::fs::write(
            directory.0.join(abi::kernel_file_name(Kind::Baseline)),
            b"invalid native image",
        )
        .unwrap();
        assert!(matches!(
            Kernel::load(&directory.0, Kind::Baseline),
            Err(LoadError::Library { .. })
        ));
        for kind in [Kind::Avx512, Kind::Avx2] {
            if kind.is_supported() {
                std::fs::write(
                    directory.0.join(abi::kernel_file_name(kind)),
                    b"invalid native image",
                )
                .unwrap();
                assert!(matches!(
                    Kernel::select(&directory.0),
                    Err(LoadError::Library { .. })
                ));
                break;
            }
        }
    }

    #[test]
    fn unsupported_simd_is_rejected_before_reading_a_native_image() {
        let directory = Installation::empty();
        for kind in [Kind::Avx512, Kind::Avx2] {
            if !kind.is_supported() {
                std::fs::write(
                    directory.0.join(abi::kernel_file_name(kind)),
                    b"invalid native image",
                )
                .unwrap();
                assert!(
                    matches!(Kernel::load(&directory.0, kind), Err(LoadError::UnsupportedCpu(rejected)) if rejected == kind)
                );
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn unc_and_device_names_are_not_kernel_installations() {
        for path in [
            r"\\server\share\kernels",
            r"\\?\UNC\server\share\kernels",
            r"\\.\C:\kernels",
        ] {
            assert!(matches!(
                Kernel::select(Path::new(path)),
                Err(LoadError::InvalidPath { .. })
            ));
        }
    }

    #[cfg(unix)]
    #[test]
    fn sibling_symlink_cannot_escape_the_trusted_directory() {
        let directory = Installation::empty();
        let outside = Installation::empty();
        let foreign = outside.0.join("outside.so");
        std::fs::write(&foreign, b"invalid native image").unwrap();
        std::os::unix::fs::symlink(
            &foreign,
            directory.0.join(abi::kernel_file_name(Kind::Baseline)),
        )
        .unwrap();
        assert!(matches!(
            Kernel::load(&directory.0, Kind::Baseline),
            Err(LoadError::InvalidPath { .. })
        ));
    }
}
