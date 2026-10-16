//! Startup-only dispatch to trusted fixed-profile SIMD proof libraries.
#![cfg_attr(not(feature = "loader"), no_std)]
#![deny(unsafe_code)]

pub mod abi;
pub use abi::Timings;

/// Maximum CPU workers in one fixed-profile proof engine, independent of ISA.
pub const MAX_PROOF_WORKERS: usize = 8;

/// Resolve a caller-provided worker request without reading process environment.
/// Invalid or zero requests use the available bounded default; valid requests
/// may lower that budget but never exceed available CPUs or the engine cap.
pub fn worker_budget(available: usize, requested: Option<&str>) -> usize {
    let default = available.clamp(1, MAX_PROOF_WORKERS);
    requested
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|count| *count > 0)
        .map_or(default, |count| count.min(default))
}

/// Deployment/descriptor identifier, independent of serialized Rust enum layouts.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Baseline = 0,
    Avx2 = 1,
    Avx512 = 2,
}
impl Kind {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::Avx2 => "avx2",
            Self::Avx512 => "avx512",
        }
    }
    pub const fn from_abi(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Baseline),
            1 => Some(Self::Avx2),
            2 => Some(Self::Avx512),
            _ => None,
        }
    }
    /// Includes OS support for saving AVX/AVX-512 register state. Called at load,
    /// never by Kernel::prove or Kernel::verify.
    #[cfg(feature = "loader")]
    pub fn is_supported(self) -> bool {
        match self {
            Self::Baseline => true,
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            Self::Avx2 => std::is_x86_feature_detected!("avx2"),
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            Self::Avx512 => {
                std::is_x86_feature_detected!("avx2")
                    && std::is_x86_feature_detected!("avx512f")
                    && std::is_x86_feature_detected!("avx512dq")
                    && std::is_x86_feature_detected!("avx512bw")
                    && std::is_x86_feature_detected!("avx512vl")
            }
            #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
            Self::Avx2 | Self::Avx512 => false,
        }
    }
}
impl core::fmt::Display for Kind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(feature = "loader")]
mod loader;
#[cfg(feature = "loader")]
pub use loader::{CallError, Kernel, LoadError, Proved};
#[cfg(feature = "loader")]
#[allow(unsafe_code)]
mod ffi;

#[cfg(test)]
mod worker_budget_tests {
    use super::*;

    #[test]
    fn requested_workers_respect_available_cpus_and_the_engine_cap() {
        for (available, expected) in [(0, 1), (1, 1), (4, 4), (8, 8), (128, 8)] {
            assert_eq!(worker_budget(available, None), expected);
            assert_eq!(worker_budget(available, Some("999")), expected);
        }
        assert_eq!(worker_budget(128, Some("2")), 2);
        assert_eq!(worker_budget(4, Some("2")), 2);
        assert_eq!(worker_budget(2, Some("4")), 2);
        assert_eq!(worker_budget(128, Some(" 3 ")), 3);
    }

    #[test]
    fn invalid_or_zero_requests_use_the_bounded_default() {
        for requested in ["", "0", "-1", "many", "184467440737095516160", "1.5"] {
            assert_eq!(worker_budget(128, Some(requested)), 8);
            assert_eq!(worker_budget(2, Some(requested)), 2);
        }
    }
}
