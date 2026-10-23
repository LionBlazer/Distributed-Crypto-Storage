//! Test-only typed CAP notifications tied to actual native proof openings.
//!
//! These are fixed receiving schemas, not geometry recovered from a root. The
//! native receiver supplies PP; its captured CAP authenticates actual decoded
//! PP opening rows below. This does not extract the complete public PP word.
use super::{Parsed, Program, Result, require, suite};
use crate::{Val, registry_progress::word::read::Evidence};
use bfv_hiding_stark::{Challenge, EXTENSION_DEGREE, QUERIES, RANDOM_CODEWORDS, SALT_ELEMENTS};
use p3_commit::Mmcs;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::Dimensions;
use p3_symmetric::MerkleCap;
use rand_public_pp::{SeedableRng, rngs::StdRng};

type Cap = MerkleCap<Val, [u8; 32]>;
type Fri = p3_fri::FriProof<
    Challenge,
    suite::ChallengeMmcs,
    Val,
    Vec<p3_fri::BatchMultiOpening<Val, suite::Mmcs>>,
>;
const INPUT_ROOT_COUNTS: [usize; 5] = [3, 3, 5, 5, 5];
const ALL_ROOT_COUNTS: [usize; 5] = [13, 13, 17, 15, 17];
const MAIN: [usize; 5] = [7161, 1656, 512, 568, 416];
const PP: [usize; 5] = [0, 0, 668, 714, 545];
const AUX_EF5: [usize; 5] = [0, 0, 82, 35, 84];
const CHUNKS: [usize; 5] = [16, 16, 8, 8, 8];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    Main,
    Pp,
    Aux,
    Quotient,
    Random,
    Fri(usize),
}
impl Role {
    fn pcs_index(self) -> Option<usize> {
        match self {
            Self::Random => Some(0),
            Self::Main => Some(1),
            Self::Quotient => Some(2),
            Self::Pp => Some(3),
            Self::Aux => Some(4),
            Self::Fri(_) => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Columns {
    Base(usize),
    Ef5(usize),
}
impl Columns {
    fn base_width(self) -> Result<usize> {
        match self {
            Self::Base(width) => Ok(width),
            Self::Ef5(width) => width
                .checked_mul(EXTENSION_DEGREE)
                .ok_or("EF width overflow".to_owned()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Matrix {
    columns: Columns,
    hiding_base_codewords: usize,
    salts: usize,
    depth: usize,
}
impl Matrix {
    fn width(&self) -> Result<usize> {
        self.columns
            .base_width()?
            .checked_add(self.hiding_base_codewords)
            .ok_or("base width overflow".to_owned())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Schema {
    role: Role,
    // Matrix order, including each matrix's separate trailing salt4, is part
    // of the type. Equal total leaf width never authorizes changing these cuts.
    matrices: Vec<Matrix>,
}
impl Schema {
    fn depth(&self) -> Result<usize> {
        let first = self.matrices.first().ok_or("empty commitment schema")?;
        require(
            self.matrices
                .iter()
                .all(|matrix| matrix.depth == first.depth),
            "commitment has more than one equal-height partition",
        )?;
        require(
            self.matrices
                .iter()
                .all(|matrix| matrix.salts == SALT_ELEMENTS)
                && SALT_ELEMENTS == 4,
            "nonfixed salt positions",
        )?;
        Ok(first.depth)
    }
    fn dimensions(&self) -> Result<Vec<Dimensions>> {
        let depth = self.depth()?;
        let height = 1usize
            .checked_shl(u32::try_from(depth).map_err(|_| "depth overflow")?)
            .ok_or("height overflow")?;
        self.matrices
            .iter()
            .map(|matrix| {
                Ok(Dimensions {
                    width: matrix.width()?,
                    height,
                })
            })
            .collect()
    }
    fn salted_width(&self) -> Result<usize> {
        self.matrices.iter().try_fold(0usize, |total, matrix| {
            total
                .checked_add(matrix.width()?)
                .and_then(|width| width.checked_add(matrix.salts))
                .ok_or("salted width overflow".to_owned())
        })
    }
}

#[derive(Debug)]
struct Notification {
    schema: Schema,
    root: [u8; 32],
    // Byte extent, not an oracle timestamp. The raw-FS parser must notify this
    // typed root when it FIRST examines a potentially canonical DRAW prefix
    // containing this extent; it cannot wait for a later Expected reveal.
    cap_end: usize,
    first_draw: usize,
}

#[derive(Default)]
pub(super) struct Counts {
    pub(super) roots: usize,
    pub(super) pp: usize,
    pub(super) authenticated_inputs: usize,
    pub(super) negative_openings: usize,
}

fn schemas(program: &Program) -> Result<Vec<Schema>> {
    let family = program.family;
    let depth = program.manifest.lde_log();
    let matrix = |columns, private| Matrix {
        columns,
        hiding_base_codewords: if private { RANDOM_CODEWORDS } else { 0 },
        salts: SALT_ELEMENTS,
        depth,
    };
    let mut result = vec![Schema {
        role: Role::Main,
        matrices: vec![matrix(Columns::Base(MAIN[family]), true)],
    }];
    if program.batch() {
        result.push(Schema {
            role: Role::Pp,
            matrices: vec![matrix(Columns::Base(PP[family]), false)],
        });
        result.push(Schema {
            role: Role::Aux,
            matrices: vec![matrix(Columns::Ef5(AUX_EF5[family]), true)],
        });
    }
    result.push(Schema {
        role: Role::Quotient,
        matrices: vec![matrix(Columns::Ef5(1), true); CHUNKS[family]],
    });
    result.push(Schema {
        role: Role::Random,
        matrices: vec![matrix(Columns::Ef5(1), true)],
    });
    for (round, depth) in program.manifest.fri_matrix_logs().enumerate() {
        result.push(Schema {
            role: Role::Fri(round),
            matrices: vec![Matrix {
                columns: Columns::Ef5(2),
                hiding_base_codewords: 0,
                salts: SALT_ELEMENTS,
                depth,
            }],
        });
    }
    require(
        result.len() == ALL_ROOT_COUNTS[family],
        "fixed CAP count changed",
    )?;
    for schema in &result {
        schema.depth()?;
        if let Some(index) = schema.role.pcs_index() {
            let actual = program
                .manifest
                .commitments()
                .get(index)
                .ok_or("missing actual PCS commitment")?;
            require(
                actual.matrices().len() == schema.matrices.len(),
                "actual PCS matrix count differs from typed schema",
            )?;
            for (actual, matrix) in actual.matrices().iter().zip(&schema.matrices) {
                require(
                    actual.width() == matrix.width()?,
                    "actual PCS base/EF5 width differs from typed schema",
                )?;
            }
            require(
                actual.salted_leaf_width() == schema.salted_width()?,
                "actual per-matrix salt cuts differ",
            )?;
        } else {
            require(
                schema.salted_width()? == program.manifest.fri_salted_leaf_width()
                    && schema.salted_width()? == 14,
                "actual binary FRI leaf schema differs",
            )?;
        }
    }
    let mut mixed = result
        .iter()
        .find(|schema| schema.role == Role::Quotient)
        .ok_or("missing quotient schema")?
        .clone();
    mixed.matrices[1].depth -= 1;
    require(
        mixed.depth().is_err(),
        "mixed-height partition passed the typed commitment gate",
    )?;
    Ok(result)
}

fn notifications(program: &Program, parsed: &Parsed, prefix: &[u8]) -> Result<Vec<Notification>> {
    let schemas = schemas(program)?;
    require(
        parsed.caps.len() == schemas.len(),
        "runtime CAP count differs from schema",
    )?;
    schemas
        .into_iter()
        .zip(&parsed.caps)
        .map(|(schema, offset)| {
            let cap_end = offset.checked_add(41).ok_or("CAP extent overflow")?;
            let bytes = prefix
                .get(*offset..cap_end)
                .ok_or("truncated captured CAP")?;
            require(
                bytes[0] == 2 && bytes[1..9] == 1u64.to_le_bytes(),
                "wrong captured CAP extent",
            )?;
            let first_draw = parsed
                .accepted
                .iter()
                .find(|sample| sample.offset >= cap_end)
                .ok_or("CAP not used by any later actual DRAW")?
                .offset;
            Ok(Notification {
                schema,
                root: bytes[9..].try_into().expect("one CAP root"),
                cap_end,
                first_draw,
            })
        })
        .collect()
}

fn root(cap: &Cap) -> Result<[u8; 32]> {
    require(
        cap.num_roots() == 1 && cap.height() == 0,
        "decoded CAP is not one root",
    )?;
    Ok(cap.roots()[0])
}
fn require_cap(notification: &Notification, cap: &Cap) -> Result<()> {
    require(
        notification.root == root(cap)?,
        "actual native proof CAP differs from captured runtime CAP",
    )
}

fn rows<T>(rows: &[Vec<Vec<T>>], schema: &Schema, salts: bool) -> Result<()> {
    require(rows.len() == QUERIES, "wrong actual query row count")?;
    for query in rows {
        require(
            query.len() == schema.matrices.len(),
            "wrong actual matrix row count",
        )?;
        for (row, matrix) in query.iter().zip(&schema.matrices) {
            let width = if salts { matrix.salts } else { matrix.width()? };
            require(
                row.len() == width,
                "actual opening row/salt width differs from typed schema",
            )?;
        }
    }
    Ok(())
}

fn inputs(
    program: &Program,
    parsed: &Parsed,
    notifications: &[Notification],
    fri: &Fri,
) -> Result<(usize, usize)> {
    let input_count = INPUT_ROOT_COUNTS[program.family];
    require(
        fri.input_openings.len() == input_count,
        "wrong decoded PCS input count",
    )?;
    let samples = parsed
        .accepted
        .get(
            parsed
                .accepted
                .len()
                .checked_sub(QUERIES)
                .ok_or("missing final samples")?..,
        )
        .ok_or("missing final query samples")?;
    let mask = (1u64
        .checked_shl(u32::try_from(program.manifest.lde_log()).map_err(|_| "index bits overflow")?)
        .ok_or("index mask overflow")?)
        - 1;
    let indices: Vec<usize> = samples
        .iter()
        .map(|sample| {
            usize::try_from(sample.value & mask).map_err(|_| "query index overflow".to_owned())
        })
        .collect::<Result<_>>()?;
    // Verification does not draw salts/RNG. This explicit PUBLIC unused stream
    // constructs only the already fixed MMCS, never a new AIR/verifier profile.
    let mmcs = suite::Mmcs::new(
        suite::LeafHash,
        suite::NodeCompress,
        0,
        StdRng::from_seed([0; 32]),
    );
    let mut negatives = 0;
    for (index, opened) in fri.input_openings.iter().enumerate() {
        let notification = notifications
            .iter()
            .find(|item| item.schema.role.pcs_index() == Some(index))
            .ok_or("missing PCS/STARK mapping")?;
        require(
            notification.schema.depth()? == program.manifest.lde_log(),
            "mixed input heights",
        )?;
        rows(&opened.opened_values, &notification.schema, false)?;
        rows(&opened.opening_proof.0, &notification.schema, true)?;
        let dimensions = notification.schema.dimensions()?;
        let cap = Cap::new(vec![notification.root]);
        mmcs.verify_multi_batch(
            &cap,
            &dimensions,
            &indices,
            &opened.opened_values,
            &opened.opening_proof,
        )
        .map_err(|error| {
            format!(
                "captured {:?} CAP/actual rows authentication: {error:?}",
                notification.schema.role
            )
        })?;
        // Small adversarial gate on the actual DATA PP opening: no new native
        // proof, arbitrary trace, synthetic leaf row or configurable verifier.
        if program.family == 2 && notification.schema.role == Role::Pp {
            let mut bad_root = notification.root;
            bad_root[0] ^= 1;
            require(
                mmcs.verify_multi_batch(
                    &Cap::new(vec![bad_root]),
                    &dimensions,
                    &indices,
                    &opened.opened_values,
                    &opened.opening_proof,
                )
                .is_err(),
                "wrong captured PP root accepted",
            )?;
            let mut row = opened.opened_values[0][0].clone();
            row[0] += Val::ONE;
            let mut borrowed: Vec<Vec<&[Val]>> = opened
                .opened_values
                .iter()
                .map(|query| query.iter().map(Vec::as_slice).collect())
                .collect();
            borrowed[0][0] = &row;
            require(
                mmcs.verify_multi_batch(
                    &cap,
                    &dimensions,
                    &indices,
                    &borrowed,
                    &opened.opening_proof,
                )
                .is_err(),
                "changed actual PP opening row accepted",
            )?;
            let mut bad_salts = opened.opening_proof.clone();
            bad_salts.0[0][0][0] += Val::ONE;
            require(
                mmcs.verify_multi_batch(
                    &cap,
                    &dimensions,
                    &indices,
                    &opened.opened_values,
                    &bad_salts,
                )
                .is_err(),
                "changed actual PP salt accepted",
            )?;
            let mut bad_dimensions = notification.schema.dimensions()?;
            bad_dimensions[0].width += 1;
            require(
                mmcs.verify_multi_batch(
                    &cap,
                    &bad_dimensions,
                    &indices,
                    &opened.opened_values,
                    &opened.opening_proof,
                )
                .is_err(),
                "changed typed matrix width accepted",
            )?;
            let mut bad_dimensions = notification.schema.dimensions()?;
            bad_dimensions[0].height *= 2;
            require(
                mmcs.verify_multi_batch(
                    &cap,
                    &bad_dimensions,
                    &indices,
                    &opened.opened_values,
                    &opened.opening_proof,
                )
                .is_err(),
                "changed typed tree depth accepted",
            )?;
            negatives += 5;
        }
    }
    Ok((input_count, negatives))
}

fn fri_openings(program: &Program, notifications: &[Notification], fri: &Fri) -> Result<()> {
    let rounds = program.manifest.fri_shape().log_arities.len();
    require(
        fri.commit_phase_commits.len() == rounds && fri.commit_phase_openings.len() == rounds,
        "wrong actual FRI round count",
    )?;
    for (round, (cap, opening)) in fri
        .commit_phase_commits
        .iter()
        .zip(&fri.commit_phase_openings)
        .enumerate()
    {
        let notification = notifications
            .iter()
            .find(|item| item.schema.role == Role::Fri(round))
            .ok_or("missing typed FRI notification")?;
        require_cap(notification, cap)?;
        require(
            notification.schema.depth()? == program.manifest.lde_log() - 1 - round,
            "wrong actual binary FRI depth",
        )?;
        require(
            opening.sibling_values.len() == QUERIES
                && opening
                    .sibling_values
                    .iter()
                    .all(|siblings| siblings.len() == 1),
            "actual FRI row does not have one sibling EF5",
        )?;
        rows(&opening.opening_proof.0, &notification.schema, true)?;
        require(
            opening.opening_proof.1.sibling_hashes.len()
                <= QUERIES * notification.schema.depth()?,
            "actual FRI frontier exceeds fixed depth",
        )?;
        // The other EF5 is computed by native fold_query, not carried here.
        // Native verification already authenticated that full two-EF row. This
        // additional test maps its cap, sibling and salts; it does not pretend
        // a metadata expansion independently captured the computed coordinate.
    }
    Ok(())
}

fn check_decoded(
    program: &Program,
    parsed: &Parsed,
    notifications: &[Notification],
    fri: &Fri,
) -> Result<Counts> {
    for sample in &parsed.accepted {
        require(
            notifications
                .iter()
                .filter(|item| item.cap_end <= sample.offset)
                .count()
                <= 17,
            "potential raw-FS notification ceiling exceeded",
        )?;
    }
    for notification in notifications {
        require(
            notification.cap_end <= notification.first_draw,
            "late typed CAP notification",
        )?;
        if matches!(notification.schema.role, Role::Main | Role::Pp) {
            require(
                notification.first_draw == parsed.accepted[0].offset,
                "MAIN/PP CAP did not precede the first actual verifier coin",
            )?;
        }
    }
    let (authenticated_inputs, negative_openings) = inputs(program, parsed, notifications, fri)?;
    fri_openings(program, notifications, fri)?;
    eprintln!(
        "hash_read typed_caps=true family={} roots={} input_commitments={authenticated_inputs} FRI_rounds={} actual_indices={} PP_authenticated={} first_MAIN_PP_before_coin=true equal_height_per_commit=true",
        super::NAMES[program.family],
        notifications.len(),
        program.manifest.fri_shape().log_arities.len(),
        QUERIES,
        program.batch(),
    );
    Ok(Counts {
        roots: notifications.len(),
        pp: usize::from(program.batch()),
        authenticated_inputs,
        negative_openings,
    })
}

/// Decode only the already accepted public fixture frames, then bind their
/// actual root/opening data to the real Challenger CAP events and fixed schema.
pub(super) fn check(
    program: &Program,
    parsed: &Parsed,
    prefix: &[u8],
    evidence: &Evidence<'_>,
) -> Result<Counts> {
    let notifications = notifications(program, parsed, prefix)?;
    let frame = match program.family {
        0 => evidence.state,
        1 => evidence.child,
        2 => evidence.data,
        3 => evidence.word,
        4 => evidence.query,
        _ => return Err("unknown fixed family".to_owned()),
    };
    let header = if program.family == 0 { 44 } else { 128 };
    let payload = frame.get(header..).ok_or("truncated genuine frame")?;
    if program.batch() {
        let proof: p3_batch_stark::BatchProof<suite::Config> = postcard::from_bytes(payload)
            .map_err(|error| format!("accepted batch proof decode: {error}"))?;
        for notification in &notifications {
            match notification.schema.role {
                Role::Main => require_cap(notification, &proof.commitments.main)?,
                Role::Aux => require_cap(
                    notification,
                    proof
                        .commitments
                        .permutation
                        .as_ref()
                        .ok_or("missing native AUX")?,
                )?,
                Role::Quotient => require_cap(notification, &proof.commitments.quotient_chunks)?,
                Role::Random => require_cap(
                    notification,
                    proof
                        .commitments
                        .random
                        .as_ref()
                        .ok_or("missing native randomization")?,
                )?,
                Role::Pp | Role::Fri(_) => {}
            }
        }
        check_decoded(program, parsed, &notifications, &proof.opening_proof.1)
    } else {
        let proof: p3_uni_stark::Proof<suite::Config> = postcard::from_bytes(payload)
            .map_err(|error| format!("accepted uni proof decode: {error}"))?;
        for notification in &notifications {
            match notification.schema.role {
                Role::Main => require_cap(notification, &proof.commitments.trace)?,
                Role::Quotient => require_cap(notification, &proof.commitments.quotient_chunks)?,
                Role::Random => require_cap(
                    notification,
                    proof
                        .commitments
                        .random
                        .as_ref()
                        .ok_or("missing native randomization")?,
                )?,
                Role::Fri(_) => {}
                Role::Pp | Role::Aux => {
                    return Err("uni proof selected batch CAP schema".to_owned());
                }
            }
        }
        check_decoded(program, parsed, &notifications, &proof.opening_proof.1)
    }
}
