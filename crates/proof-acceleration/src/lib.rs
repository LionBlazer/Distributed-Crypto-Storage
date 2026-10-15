//! Startup-only dispatch to trusted fixed-profile SIMD proof libraries.
#![cfg_attr(not(feature = "loader"), no_std)]
#![deny(unsafe_code)]

pub mod abi;
pub use abi::Timings;

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
