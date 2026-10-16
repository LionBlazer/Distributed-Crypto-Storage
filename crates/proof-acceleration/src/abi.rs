//! Versioned, fixed-profile C ABI shared by the baseline host and trusted kernels.
//! No Rust allocation, reference, enum layout, error object or secret crosses this ABI.
use crate::Kind;

pub const ABI_VERSION: u32 = 1;
pub const MAX_INPUT_BYTES: usize = 1_310_760;
pub const OUTPUT_BYTES: usize = 655_400;
pub const MAX_OUTPUT_BYTES: usize = OUTPUT_BYTES;
pub const MAX_PROOF_BYTES: usize = 2_097_152;
/// SHA-256 of PROFILE_DESCRIPTION; SIMD selection does not change this statement.
pub const PROFILE_ID: [u8; 32] = [
    211, 249, 182, 167, 98, 174, 126, 153, 192, 193, 147, 147, 202, 193, 44, 99, 191, 191, 106, 17,
    80, 54, 248, 57, 32, 224, 179, 186, 12, 7, 227, 67,
];
pub const PROFILE_DESCRIPTION: &[u8] = b"dcs-proof-backend-profile/v3\nbfv:N=8192;t=114689;Q=[8796092858369,8796092792833,17592186028033,17592185438209,17592184717313];CBD20-variance10;components=2;level=0;representation=NTT\ncanonical:add=BFVLADQ1/BFVLADR1;product=BFVPMUQ1/BFVPMUR1;coefficients=81920;sha256-original-request-binding\nproof:add=BFVP3A03;product=BFVP3M04;public-auxiliary=81920*(6+3+3);limb-base=4194304;quotient-bits=44;carry-bits=23,24;lanes=10;height=8192;layout=polynomial-lanes;modulus=lane-fixed;public-columns=30,100\np3=0.8.0;field=Goldilocks;extension=Binomial5;Poseidon2-default-Goldilocks-width12;sponge=12,8,4;compression=2,4,12;MMCS-cap=0;FRI-blowup=8;queries=192;final-poly-log=0;max-arity-log=1;grinding=0,0,0;security-model-min=128\ntranscript=sha256-input,sha256-output,sha256-product-aux;codec=postcard1.1.3;sequence-limit=4096;decode-slots=1048576;proof-cap=2097152\n";

pub const SUCCESS: u32 = 0;
pub const STATEMENT_SHAPE: u32 = 1;
pub const REQUEST_BINDING: u32 = 2;
pub const NON_CANONICAL_RESIDUE: u32 = 3;
pub const PROOF_LENGTH: u32 = 4;
pub const PROOF_ENCODING: u32 = 5;
pub const PROOF_RESOURCE_LIMIT: u32 = 6;
pub const TRAILING_PROOF_BYTES: u32 = 7;
pub const SECURITY_PROFILE: u32 = 8;
pub const PREPROCESSING: u32 = 9;
pub const PROVING: u32 = 10;
pub const VERIFICATION: u32 = 11;
pub const INVALID_ABI: u32 = 12;
pub const BUFFER_TOO_SMALL: u32 = 13;
pub const PANIC: u32 = 14;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Span {
    pub ptr: *const u8,
    pub len: usize,
}
impl Span {
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self {
            ptr: bytes.as_ptr(),
            len: bytes.len(),
        }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Buffer {
    pub ptr: *mut u8,
    pub capacity: usize,
    pub written: usize,
}
impl Buffer {
    pub fn from_slice(bytes: &mut [u8]) -> Self {
        Self {
            ptr: bytes.as_mut_ptr(),
            capacity: bytes.len(),
            written: 0,
        }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timings {
    pub operation_ns: u64,
    pub preprocessing_ns: u64,
    pub proof_ns: u64,
    pub total_ns: u64,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Descriptor {
    pub abi_version: u32,
    pub kind: u32,
    pub profile_id: [u8; 32],
}
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ProveCall {
    pub input: Span,
    pub output: Buffer,
    pub proof: Buffer,
    pub timings: Timings,
}
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct VerifyCall {
    pub input: Span,
    pub output: Span,
    pub proof: Span,
    pub timings: Timings,
}

pub type InfoFn = unsafe extern "C" fn(*mut Descriptor) -> u32;
pub type ProveFn = unsafe extern "C" fn(*mut ProveCall) -> u32;
pub type VerifyFn = unsafe extern "C" fn(*mut VerifyCall) -> u32;
pub const INFO_SYMBOL: &[u8] = b"dcs_proof_backend_info_v1\0";
pub const PROVE_SYMBOL: &[u8] = b"dcs_proof_backend_prove_v1\0";
pub const VERIFY_SYMBOL: &[u8] = b"dcs_proof_backend_verify_v1\0";

/// Exact sibling filenames; no PATH/CWD lookup or arbitrary plugin name is accepted.
pub const fn kernel_file_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Baseline => {
            #[cfg(windows)]
            {
                "dcs-proof-baseline.dll"
            }
            #[cfg(target_os = "macos")]
            {
                "libdcs-proof-baseline.dylib"
            }
            #[cfg(all(not(windows), not(target_os = "macos")))]
            {
                "libdcs-proof-baseline.so"
            }
        }
        Kind::Avx2 => {
            #[cfg(windows)]
            {
                "dcs-proof-avx2.dll"
            }
            #[cfg(target_os = "macos")]
            {
                "libdcs-proof-avx2.dylib"
            }
            #[cfg(all(not(windows), not(target_os = "macos")))]
            {
                "libdcs-proof-avx2.so"
            }
        }
        Kind::Avx512 => {
            #[cfg(windows)]
            {
                "dcs-proof-avx512.dll"
            }
            #[cfg(target_os = "macos")]
            {
                "libdcs-proof-avx512.dylib"
            }
            #[cfg(all(not(windows), not(target_os = "macos")))]
            {
                "libdcs-proof-avx512.so"
            }
        }
    }
}
