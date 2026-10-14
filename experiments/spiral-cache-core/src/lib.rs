//! Safe scheduling of the pinned SDK's public database conversion.
//! Based on Spiral server::load_db_from_seek at SDK fdb72065 (MIT).
#![forbid(unsafe_code)]
use rayon::prelude::*;
use spiral_rs::{
    aligned_memory::AlignedMemory64, arith::recenter_mod, params::Params,
    server::load_item_from_seek,
};
use std::io::Cursor;

pub const RECORD_BYTES: usize = 8192;
pub const RECORD_SLOTS: usize = 512;
pub const RECORD_IMAGE_BYTES: usize = RECORD_BYTES * RECORD_SLOTS;
pub const CACHE_BYTES: usize = 33_554_432;
const PACKED_SECOND_RESIDUE: u32 = 32;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    UnsupportedProfile,
    RecordImageLength { expected: usize, actual: usize },
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Spiral cache conversion: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Exact current native PIR profile; no owner keys or storage policy.
pub fn profile_params() -> Params {
    Params::init(
        2048,
        &[268_369_921, 249_561_089],
        6.4,
        2,
        256,
        20,
        4,
        8,
        56,
        8,
        true,
        7,
        2,
        1,
        RECORD_BYTES,
        0,
    )
}
fn validate(params: &Params, records: &[u8]) -> Result<(), Error> {
    if *params != profile_params() {
        return Err(Error::UnsupportedProfile);
    }
    if records.len() != RECORD_IMAGE_BYTES {
        return Err(Error::RecordImageLength {
            expected: RECORD_IMAGE_BYTES,
            actual: records.len(),
        });
    }
    Ok(())
}
fn convert(params: &Params, records: &[u8]) -> AlignedMemory64 {
    // Validation fixes all dimensions before these bounded products/shifts.
    let trials = params.n * params.n;
    let dim0 = 1usize << params.db_dim_1;
    let num_per = 1usize << params.db_dim_2;
    let items = dim0 * num_per;
    let slab_words = params.poly_len * items;
    let mut output = AlignedMemory64::new(params.instances * trials * slab_words);
    output
        .as_mut_slice()
        .par_chunks_mut(slab_words)
        .enumerate()
        .for_each(|(slab_id, slab)| {
            let instance = slab_id / trials;
            let trial = slab_id % trials;
            // Each task has an independent Cursor over shared immutable public records.
            let mut cursor = Cursor::new(records);
            for item in 0..items {
                let mut polynomial =
                    load_item_from_seek(params, &mut cursor, instance, trial, item);
                for value in polynomial.data.as_mut_slice().iter_mut() {
                    *value = recenter_mod(*value, params.pt_modulus, params.modulus);
                }
                let ntt = polynomial.ntt();
                for z in 0..params.poly_len {
                    let destination = (z * num_per + item % num_per) * dim0 + item / num_per;
                    slab[destination] =
                        ntt.data[z] | (ntt.data[params.poly_len + z] << PACKED_SECOND_RESIDUE);
                }
            }
        });
    output
}

/// Convert one exact fixed-profile record image using four disjoint trial slabs.
/// The caller owns its Rayon pool, admission budget and resulting cache lifetime.
pub fn load_records(params: &Params, records: &[u8]) -> Result<AlignedMemory64, Error> {
    validate(params, records)?;
    Ok(convert(params, records))
}

/// Convert independent data/index images concurrently in the caller's same pool.
/// Both inputs are validated before either 32 MiB output allocation.
pub fn load_pair(
    params: &Params,
    data: &[u8],
    index: &[u8],
) -> Result<(AlignedMemory64, AlignedMemory64), Error> {
    validate(params, data)?;
    validate(params, index)?;
    Ok(rayon::join(
        || convert(params, data),
        || convert(params, index),
    ))
}
