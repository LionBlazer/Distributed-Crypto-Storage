//! Analysis-only canonical public-factory association BEFORE a first coin.
//!
//! The input P stream must come from the separately first-frozen typed Merkle
//! snapshot. This reader cannot authenticate that external extraction history.
//! It checks ALL five public factories without a secret, proof, Config or RNG.
//! No production module, accepted native result or security grant imports this.
use super::{air::ProgramAir, complete_role, goldens, plan::Plan};
use crate::{Val, source, two_lane_encoding as encoding};
use compact_store::Commitment;
use p3_air::BaseAir;
use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::{Matrix, bitrev::BitReversibleMatrix, dense::RowMajorMatrix};
use std::io::Read;

mod first_coin;
#[cfg(test)]
mod tests;

const MAGIC: &[u8; 8] = b"DCSMUB01";
const PUBLIC: [usize; 5] = [691, 740, 32, 309, 32];
const PP: [usize; 5] = [0, 0, 668, 714, 545];
const K: [usize; 5] = [1024, 1024, 4096, 1024, 4096];
const DEPTH: [u8; 5] = [0, 0, 15, 13, 15];
type Result<T> = core::result::Result<T, &'static str>;

/// A private analysis descriptor, never a checked-proof or journal capability.
#[derive(Debug)]
struct Association {
    family: usize,
    public: Vec<Val>,
    pp_pin: Option<([u8; 32], u64)>,
    columns: usize,
}

fn bytes32(values: &[Val]) -> Result<[u8; 32]> {
    packed_bytes(values)?
        .try_into()
        .map_err(|_| "public-bytes32")
}

fn packed_bytes(values: &[Val]) -> Result<Vec<u8>> {
    let mut result = Vec::with_capacity(values.len() * 4);
    for value in values {
        let word = u32::try_from(value.as_canonical_u64()).map_err(|_| "public-u32")?;
        result.extend(word.to_le_bytes());
    }
    Ok(result)
}

fn four(values: &[Val]) -> Result<[Val; 4]> {
    values.try_into().map_err(|_| "public-root4")
}

/// Complete PUBLIC parse, not an inverse of any digest or hidden Expected.
fn source_from_public(values: &[Val]) -> Result<source::version::SourceVersionExpected> {
    if values.len() != 691 {
        return Err("source-public-width");
    }
    // The public layout is profile8/request8/head28/head28/packet15/packet596/
    // key4/state4. The owning constructors recheck every head/image/root byte.
    let heads = [
        packed_bytes(&values[16..44])?,
        packed_bytes(&values[44..72])?,
    ];
    let heads = [
        Commitment::decode(&heads[0], source::statement::limits()).map_err(|_| "source-head")?,
        Commitment::decode(&heads[1], source::statement::limits()).map_err(|_| "source-head")?,
    ];
    let packets = [
        packed_bytes(&values[72..87])?,
        packed_bytes(&values[87..683])?,
    ];
    let images: [Vec<u8>; 2] = core::array::from_fn(|i| {
        let mut bytes = heads[i].encode().to_vec();
        bytes.extend(&packets[i]);
        bytes
    });
    let expected = source::version::SourceVersionExpected::checked(
        [&images[0], &images[1]],
        [&heads[0], &heads[1]],
        source::statement::encode_digest(four(&values[683..687])?),
        source::statement::encode_digest(four(&values[687..691])?),
    )
    .map_err(|_| "source-complete-image")?;
    // Includes the exact StateCertificate profile AND recomputed version_tag;
    // request/profile words are not ignored after reconstructing the images.
    if expected.statement().values() != values {
        return Err("source-profile-or-version-tag");
    }
    Ok(expected)
}

fn role3_from_public(values: &[Val]) -> Result<encoding::statement::Statement> {
    if values.len() != 740 {
        return Err("role3-public-width");
    }
    let source = source_from_public(&values[8..699])?;
    let key = &values[699..728];
    let key = encoding::statement::KeyBinding::new(
        packed_bytes(&key[..4])?
            .try_into()
            .map_err(|_| "role3-db")?,
        packed_bytes(&key[4..8])?
            .try_into()
            .map_err(|_| "role3-domain")?,
        u32::try_from(key[8].as_canonical_u64()).map_err(|_| "role3-epoch")?,
        bytes32(&key[17..25])?,
        source::statement::encode_digest(four(&key[25..29])?),
    )
    .map_err(|_| "role3-key")?;
    let expected = encoding::statement::Expected::source_version(&source, key)
        .map_err(|_| "role3-source-link")?;
    let statement = encoding::statement::Statement {
        expected,
        encoded: four(&values[736..740])?,
    };
    // Exact Role3 profile, candidate parameter label, complete source, key29,
    // acyclic base/encoding contexts and canonical Cw all remain in this check.
    if statement.values() != values {
        return Err("role3-profile-key-or-context");
    }
    Ok(statement)
}

fn word_pp() -> Result<RowMajorMatrix<Val>> {
    let built = complete_role(true).map_err(|_| "word-factory")?;
    let plan = Plan::new(built.pool).map_err(|_| "word-plan")?;
    goldens::require_plan(&plan).map_err(|_| "word-original-regression")?;
    let air = ProgramAir { plan };
    let original = air.preprocessed_trace().ok_or("word-preprocessed")?;
    if original.height() != 512 || original.width() != 714 {
        return Err("word-fixed-shape");
    }
    // EXACT public hiding_pcs::commit_preprocessing: zero-interleave 512→1024
    // rows before the inner PCS's blowup8 coset LDE. No private seeded config.
    let mut padded = original.with_zero_cols(714);
    padded.width = 714;
    Ok(Radix2DitParallel::default()
        .coset_lde_batch(padded, 3, Val::from_u64(7))
        .bit_reverse_rows()
        .to_row_major_matrix())
}

fn field(reader: &mut impl Read) -> Result<Val> {
    let mut bytes = [0; 8];
    reader
        .read_exact(&mut bytes)
        .map_err(|_| "truncated-field")?;
    let word = u64::from_le_bytes(bytes);
    if word >= Val::ORDER_U64 {
        return Err("noncanonical-Gold");
    }
    Ok(Val::from_u64(word))
}

fn low_degree(column: Vec<Val>, k: usize) -> Result<()> {
    if column.iter().all(|value| *value == column[0]) {
        return Ok(());
    }
    // Native stream order is bit-reversed x=7*K. Unpermute once, then use the
    // actual base-field inverse coset transform. Only O(n) one-column storage.
    let natural = RowMajorMatrix::new_col(column)
        .bit_reverse_rows()
        .to_row_major_matrix();
    let coefficients = Radix2DitParallel::default().coset_idft_batch(natural, Val::from_u64(7));
    if coefficients.values[k..]
        .iter()
        .any(|value| *value != Val::ZERO)
    {
        return Err("PP-degree-reaches-k");
    }
    Ok(())
}

/// The single fixed all-five classifier, called synchronously BEFORE any coin.
///
/// Header64: magic8, family1, PP-depth1, zero6, PP-root32, first-cutoff8, zero8.
/// Then exact shaped canonical Gold PVs and complete PP columns, each in native
/// physical order. No PP salt, random codeword, configurable geometry or expected
/// commitment is accepted. Source/Role3 require the absent-PP pin to be zero.
fn read_before_first_coin(reader: &mut impl Read) -> Result<Association> {
    let mut header = [0; 64];
    reader
        .read_exact(&mut header)
        .map_err(|_| "truncated-header")?;
    if &header[..8] != MAGIC || header[10..16] != [0; 6] || header[56..64] != [0; 8] {
        return Err("canonical-header");
    }
    let family = usize::from(header[8]);
    if family >= PUBLIC.len() || header[9] != DEPTH[family] {
        return Err("closed-family-depth");
    }
    let root: [u8; 32] = header[16..48].try_into().map_err(|_| "root")?;
    let cutoff = u64::from_le_bytes(header[48..56].try_into().map_err(|_| "cutoff")?);
    let has_pp = PP[family] != 0;
    if !has_pp && (root != [0; 32] || cutoff != 0) {
        return Err("unexpected-PP-notification");
    }
    let public = (0..PUBLIC[family])
        .map(|_| field(reader))
        .collect::<Result<Vec<_>>>()?;
    match family {
        0 => {
            source_from_public(&public)?;
        }
        1 => {
            role3_from_public(&public)?;
        }
        // These lexical AIRs have no Expected-dependent coefficient other than
        // their full PV pins. Word's PP is fixed; DATA/Query's is generalized.
        2..=4 => {}
        _ => unreachable!(),
    }
    let fixed_word = if family == 3 { Some(word_pp()?) } else { None };
    let n = if has_pp { 1usize << DEPTH[family] } else { 0 };
    for column in 0..PP[family] {
        let values = (0..n).map(|_| field(reader)).collect::<Result<Vec<_>>>()?;
        if let Some(expected) = &fixed_word {
            if values
                .iter()
                .enumerate()
                .any(|(row, value)| *value != expected.values[row * PP[family] + column])
            {
                return Err("Word-PP-differs-from-genuine-fixed-factory");
            }
            // Equality to the actual 1024-row public interpolation already
            // proves degree<1024; do not repeat 714 inverse FFTs needlessly.
        } else {
            low_degree(values, K[family])?;
        }
    }
    let mut extra = [0; 1];
    if reader.read(&mut extra).map_err(|_| "trailing-read")? != 0 {
        return Err("trailing-input");
    }
    Ok(Association {
        family,
        public,
        pp_pin: has_pp.then_some((root, cutoff)),
        columns: PP[family],
    })
}
