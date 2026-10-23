//! Test-only recognizer of five complete, actual native receiving transcripts.
//!
//! The native verifier, not this parser, constructs the PP commitments. Their
//! opaque CAP bytes are captured here; there is no inverse of PP/Expected and no
//! online Merkle extractor, adaptive-ROM simulation or admission certificate.
use crate::{
    Val,
    registry_progress::word::read::{Expected, transcript},
    source,
};
use bfv_hiding_stark::{
    EXTENSION_DEGREE, LOG_BLOWUP, QUERIES,
    hash::{
        self as suite,
        audit::{Draw, Trace},
    },
    transcript::ArgumentManifest,
};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use sha2::{Digest, Sha512};

type Result<T> = core::result::Result<T, String>;
const FIELD: u8 = 1;
const CAP: u8 = 2;
const SAMPLE: u8 = 3;
const DRAW: u8 = 4;
const MAX_PREFIX: usize = 8 * 1024 * 1024;
const NAMES: [&str; 5] = ["Source", "Role3", "DATA", "Word", "Query"];
const PUBLIC_COUNTS: [usize; 5] = [691, 740, 32, 309, 32];
const OPENING_COUNTS: [usize; 5] = [14502, 3492, 2622, 3024, 2327];
const COMMITTED_LOGS: [usize; 5] = [10, 10, 12, 10, 12];
const GROUP_COUNTS: [usize; 5] = [14, 14, 17, 15, 17];
const SAMPLE_COUNTS: [usize; 5] = [257, 257, 277, 267, 277];

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}

struct Program {
    manifest: ArgumentManifest,
    public: Vec<Val>,
    seed: Vec<u8>,
    family: usize,
}
impl Program {
    fn batch(&self) -> bool {
        self.family >= 2
    }

    fn groups(&self) -> Result<Vec<usize>> {
        let mut groups = Vec::new();
        for separator in [
            self.manifest.stark(),
            self.manifest.pcs(),
            self.manifest.fri(),
        ] {
            groups.extend(
                separator
                    .challenge_group_base_draws()
                    .map_err(|e| e.to_string())?,
            );
        }
        Ok(groups)
    }
}

// Independently concatenate the public Word fields through its owning API;
// do not call the private production PV serializer to recreate its own output.
fn word_values(expected: &Expected) -> Vec<Val> {
    let word = expected.word_expected();
    let source = word.source().statement();
    let claims = word.claims();
    let mut values = source::commitment::prefix(source, [Val::ZERO; 4])[..83].to_vec();
    values.extend(source.open_commitment);
    values.extend(word.registry_header());
    values.extend(word.enrollment_header());
    values.extend(word.context());
    values.extend(word.scope());
    values.extend(source::statement::words(&word.parent()));
    values.extend(word.statement_domain().enrollment);
    for root in [
        claims.old,
        claims.command,
        claims.statement,
        claims.next,
        claims.result,
    ] {
        values.extend(root);
    }
    values.extend(claims.blind_sql);
    values
}

fn programs(expected: &Expected) -> Result<[Program; 5]> {
    let manifests = transcript::inspect(expected).map_err(|e| e.to_string())?;
    let public = [
        expected.word_expected().source().statement().values(),
        expected.data_expected().source().values(),
        expected.data_expected().core_expected().values().to_vec(),
        word_values(expected),
        expected.query_expected().core_expected().values().to_vec(),
    ];
    let mut pairs = manifests.into_iter().zip(public).enumerate();
    let programs: [Program; 5] = core::array::from_fn(|_| {
        let (family, (manifest, public)) = pairs.next().expect("five closed programs");
        let mut seed = Vec::new();
        for field in manifest.stark().observed_fields() {
            seed.push(FIELD);
            seed.extend(field.as_canonical_u64().to_le_bytes());
        }
        Program {
            manifest,
            public,
            seed,
            family,
        }
    });
    for (i, program) in programs.iter().enumerate() {
        require(
            program.public.len() == PUBLIC_COUNTS[i],
            "actual public width changed",
        )?;
        require(
            program.manifest.lde_log() == COMMITTED_LOGS[i] + LOG_BLOWUP,
            "actual degree changed",
        )?;
        let shape = program.manifest.fri_shape();
        require(
            shape.log_arities == vec![1; COMMITTED_LOGS[i]],
            "actual FRI schedule changed",
        )?;
        require(
            shape.final_poly_len == 1 && shape.num_queries == QUERIES && QUERIES == 192,
            "actual FRI final/query shape changed",
        )?;
        require(
            shape.commit_pow_bits == 0
                && shape.query_pow_bits == 0
                && program.manifest.pcs_shape().batch_pow_bits == 0,
            "nonzero grinding",
        )?;
        require(
            shape.index_bits == program.manifest.lde_log(),
            "actual index projection changed",
        )?;
        require(
            program.groups()?.len() == GROUP_COUNTS[i],
            "actual challenge groups changed",
        )?;
        for (j, other) in programs.iter().enumerate() {
            if i != j {
                require(
                    !program.seed.starts_with(&other.seed),
                    "closed seeds are not prefix-free",
                )?;
            }
        }
    }
    Ok(programs)
}

#[derive(Clone, Copy)]
struct View<'a> {
    prefix: &'a [u8],
    draws: &'a [Draw],
}
#[derive(Clone, Copy)]
struct Accepted {
    offset: usize,
    counter: u64,
    value: u64,
}
struct Parsed {
    accepted: Vec<Accepted>,
    groups: Vec<usize>,
    public_offset: usize,
    opening_offset: usize,
    caps: Vec<usize>,
    pp: Option<[u8; 32]>,
}
struct Parser<'a> {
    bytes: &'a [u8],
    cursor: usize,
    parsed: Parsed,
}
impl<'a> Parser<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self> {
        require(bytes.len() <= MAX_PREFIX, "trace exceeds capture limit")?;
        require(
            bytes.starts_with(suite::TRANSCRIPT_DOMAIN),
            "wrong transcript domain",
        )?;
        Ok(Self {
            bytes,
            cursor: suite::TRANSCRIPT_DOMAIN.len(),
            parsed: Parsed {
                accepted: Vec::new(),
                groups: Vec::new(),
                public_offset: 0,
                opening_offset: 0,
                caps: Vec::new(),
                pp: None,
            },
        })
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or("trace extent overflow")?;
        let bytes = self.bytes.get(self.cursor..end).ok_or("truncated trace")?;
        self.cursor = end;
        Ok(bytes)
    }
    fn tag(&mut self, expected: u8) -> Result<()> {
        require(self.take(1)? == [expected], "unexpected runtime event")
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().expect("eight checked bytes"),
        ))
    }
    fn field(&mut self) -> Result<u64> {
        self.tag(FIELD)?;
        let value = self.u64()?;
        require(value < Val::ORDER_U64, "noncanonical FIELD")?;
        Ok(value)
    }
    fn fields(&mut self, expected: &[Val]) -> Result<()> {
        for field in expected {
            require(
                self.field()? == field.as_canonical_u64(),
                "wrong seed/public FIELD",
            )?;
        }
        Ok(())
    }
    fn opaque_fields(&mut self, count: usize) -> Result<()> {
        for _ in 0..count {
            self.field()?;
        }
        Ok(())
    }
    fn cap(&mut self) -> Result<[u8; 32]> {
        self.parsed.caps.push(self.cursor);
        self.tag(CAP)?;
        require(self.u64()? == 1, "closed cap does not have one root")?;
        Ok(self.take(32)?.try_into().expect("one checked root"))
    }
    fn group(&mut self, count: usize) -> Result<()> {
        self.parsed.groups.push(count);
        for _ in 0..count {
            let offset = self.cursor;
            self.tag(SAMPLE)?;
            let counter = self.u64()?;
            require(
                counter
                    == u64::try_from(self.parsed.accepted.len()).map_err(|_| "counter overflow")?,
                "skipped/repeated SAMPLE counter",
            )?;
            let value = self.u64()?;
            require(value < Val::ORDER_U64, "noncanonical SAMPLE")?;
            self.parsed.accepted.push(Accepted {
                offset,
                counter,
                value,
            });
        }
        Ok(())
    }
}

fn parse(program: &Program, prefix: &[u8]) -> Result<Parsed> {
    let mut parser = Parser::new(prefix)?;
    let manifest = &program.manifest;
    parser.fields(manifest.stark().observed_fields())?;
    if program.batch() {
        let degree = manifest
            .lde_log()
            .checked_sub(LOG_BLOWUP)
            .ok_or("invalid degree")?;
        let degree = u64::try_from(degree).map_err(|_| "degree overflow")?;
        parser.fields(&[
            Val::from_u64(degree),
            Val::ZERO,
            Val::ZERO,
            Val::ZERO,
            Val::ZERO,
        ])?;
    }
    parser.cap()?;
    parser.parsed.public_offset = parser.cursor;
    parser.fields(&program.public)?;
    if program.batch() {
        parser.parsed.pp = Some(parser.cap()?);
        parser.group(2 * EXTENSION_DEGREE)?;
        parser.cap()?;
        parser.fields(&[Val::ZERO; EXTENSION_DEGREE])?;
    }
    parser.group(EXTENSION_DEGREE)?;
    parser.cap()?;
    parser.cap()?;
    parser.group(EXTENSION_DEGREE)?;
    parser.fields(manifest.pcs().observed_fields())?;
    let openings = manifest
        .pcs_shape()
        .claimed_evaluation_counts
        .iter()
        .flatten()
        .flatten()
        .try_fold(0usize, |total, count| total.checked_add(*count))
        .ok_or("opening count overflow")?;
    require(
        openings == OPENING_COUNTS[program.family],
        "actual opening inventory changed",
    )?;
    parser.parsed.opening_offset = parser.cursor;
    parser.opaque_fields(
        openings
            .checked_mul(EXTENSION_DEGREE)
            .ok_or("opening width overflow")?,
    )?;
    parser.group(EXTENSION_DEGREE)?;
    parser.fields(manifest.fri().observed_fields())?;
    for _ in &manifest.fri_shape().log_arities {
        parser.cap()?;
        parser.group(EXTENSION_DEGREE)?;
    }
    parser.opaque_fields(
        manifest
            .fri_shape()
            .final_poly_len
            .checked_mul(EXTENSION_DEGREE)
            .ok_or("final polynomial width overflow")?,
    )?;
    parser.group(manifest.fri_shape().num_queries)?;
    require(parser.cursor == prefix.len(), "trailing runtime event")?;
    require(
        parser.parsed.groups == program.groups()?,
        "actual challenge grouping differs from SDK pattern",
    )?;
    require(
        parser.parsed.accepted.len() == SAMPLE_COUNTS[program.family],
        "wrong accepted draw count",
    )?;
    Ok(parser.parsed)
}

// Hash each absorbed byte once. Cloning this incremental state at the recorded
// DRAW boundary is exactly SHA512(raw prefix || DRAW || counter || retry), without
// quadratic allocation or repeatedly hashing every earlier byte.
fn verify_draws(view: View<'_>, accepted: &[Accepted]) -> Result<usize> {
    let mut state = Sha512::new();
    let mut absorbed = 0usize;
    let mut draws = view.draws.iter();
    let mut attempts = 0usize;
    for sample in accepted {
        require(sample.offset >= absorbed, "nonmonotonic event position")?;
        state.update(&view.prefix[absorbed..sample.offset]);
        absorbed = sample.offset;
        let mut retry = 0u64;
        loop {
            let draw = draws.next().ok_or("SAMPLE without actual DRAW")?;
            require(
                draw.prefix_len() == sample.offset
                    && draw.counter() == sample.counter
                    && draw.retry() == retry,
                "DRAW prefix/counter/retry mismatch",
            )?;
            let mut hash = state.clone();
            hash.update([DRAW]);
            hash.update(sample.counter.to_le_bytes());
            hash.update(retry.to_le_bytes());
            let digest: [u8; 64] = hash.finalize().into();
            require(
                &digest == draw.digest(),
                "actual DRAW digest differs from raw preimage",
            )?;
            attempts = attempts.checked_add(1).ok_or("attempt count overflow")?;
            let candidate = u64::from_le_bytes(digest[..8].try_into().expect("digest prefix"));
            if candidate < Val::ORDER_U64 {
                require(
                    candidate == sample.value,
                    "SAMPLE differs from accepted DRAW",
                )?;
                break;
            }
            retry = retry.checked_add(1).ok_or("retry counter overflow")?;
        }
    }
    require(draws.next().is_none(), "extra/unaccepted actual DRAW")?;
    Ok(attempts)
}

fn recognize(program: &Program, view: View<'_>) -> Result<Parsed> {
    let parsed = parse(program, view.prefix)?;
    verify_draws(view, &parsed.accepted)?;
    Ok(parsed)
}

fn changed_field(bytes: &mut [u8], offset: usize) {
    let old = u64::from_le_bytes(bytes[offset + 1..offset + 9].try_into().expect("FIELD"));
    let changed = if old + 1 == Val::ORDER_U64 {
        0
    } else {
        old + 1
    };
    bytes[offset + 1..offset + 9].copy_from_slice(&changed.to_le_bytes());
}

fn reject_mutations(program: &Program, view: View<'_>, parsed: &Parsed) -> Result<usize> {
    let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();
    let mut changed = view.prefix.to_vec();
    changed_field(&mut changed, suite::TRANSCRIPT_DOMAIN.len());
    cases.push(("changed seed with unchanged manifest", changed));
    let mut changed = view.prefix.to_vec();
    changed_field(&mut changed, parsed.public_offset);
    cases.push(("changed independently retained PV", changed));
    let mut changed = view.prefix.to_vec();
    changed[parsed.public_offset + 1..parsed.public_offset + 9]
        .copy_from_slice(&Val::ORDER_U64.to_le_bytes());
    cases.push(("noncanonical FIELD", changed));
    let mut changed = view.prefix.to_vec();
    changed.drain(parsed.public_offset..parsed.public_offset + 9);
    cases.push(("omitted observation", changed));
    let mut changed = view.prefix.to_vec();
    changed.splice(
        parsed.public_offset..parsed.public_offset,
        [FIELD, 0, 0, 0, 0, 0, 0, 0, 0],
    );
    cases.push(("inserted observation", changed));
    let unequal = program
        .public
        .windows(2)
        .position(|fields| fields[0] != fields[1])
        .ok_or("fixture needs two distinct public observations")?;
    let left = parsed.public_offset + 9 * unequal;
    let mut changed = view.prefix.to_vec();
    let (head, tail) = changed.split_at_mut(left + 9);
    head[left..left + 9].swap_with_slice(&mut tail[..9]);
    cases.push(("reordered observations", changed));
    let first = parsed.accepted.first().ok_or("empty native transcript")?;
    let mut changed = view.prefix.to_vec();
    changed[first.offset + 1..first.offset + 9].copy_from_slice(&1u64.to_le_bytes());
    cases.push(("skipped SAMPLE counter", changed));
    let mut changed = view.prefix.to_vec();
    let value = if first.value + 1 == Val::ORDER_U64 {
        0
    } else {
        first.value + 1
    };
    changed[first.offset + 9..first.offset + 17].copy_from_slice(&value.to_le_bytes());
    cases.push(("false accepted SAMPLE history", changed));
    for roots in [0u64, 2, u64::MAX] {
        let mut changed = view.prefix.to_vec();
        let offset = parsed.caps[0];
        changed[offset + 1..offset + 9].copy_from_slice(&roots.to_le_bytes());
        cases.push(("nonclosed CAP count", changed));
    }
    let mut changed = view.prefix.to_vec();
    changed[parsed.caps[0] + 9] ^= 1;
    cases.push(("changed opaque cap without fresh draws", changed));
    let mut changed = view.prefix.to_vec();
    changed_field(&mut changed, parsed.opening_offset);
    cases.push(("changed claimed opening without fresh draws", changed));
    if program.batch() {
        let mut changed = view.prefix.to_vec();
        changed[parsed.caps[1] + 9] ^= 1;
        cases.push(("changed receiver PP cap without fresh draws", changed));
    }
    cases.push((
        "truncated SAMPLE",
        view.prefix[..view.prefix.len() - 1].to_vec(),
    ));
    let mut changed = view.prefix.to_vec();
    changed.push(FIELD);
    cases.push(("trailing event", changed));
    for (name, bytes) in &cases {
        require(
            recognize(
                program,
                View {
                    prefix: bytes,
                    draws: view.draws,
                },
            )
            .is_err(),
            &format!("mutated runtime trace accepted: {name}"),
        )?;
    }
    Ok(cases.len())
}

/// Invoke only after capture around genuine `Verifier::new(...).verify_and_retain`.
/// No synthetic challenger driver, metadata-expanded event list or proof replay
/// substitutes for those actual receiving calls. Mutation checks reuse that same
/// captured stream and add no native proofs or verification invocations.
pub(super) fn check(expected: &Expected, traces: &[Trace]) -> Result<()> {
    require(traces.len() <= 64, "capture exceeded trace bound")?;
    let programs = programs(expected)?;
    let mut seen = [false; 5];
    let mut groups = 0usize;
    let mut samples = 0usize;
    let mut attempts = 0usize;
    let mut mutations = 0usize;
    let mut pp_caps = Vec::new();
    let mut inactive = 0usize;
    for trace in traces {
        if trace.draws().is_empty() {
            require(
                trace.prefix() == suite::TRANSCRIPT_DOMAIN,
                "unexpected incomplete native trace",
            )?;
            inactive += 1;
            continue;
        }
        let prefix = trace.prefix();
        require(
            prefix.starts_with(suite::TRANSCRIPT_DOMAIN),
            "wrong active transcript domain",
        )?;
        let tail = &prefix[suite::TRANSCRIPT_DOMAIN.len()..];
        let matching: Vec<_> = programs
            .iter()
            .filter(|program| tail.starts_with(&program.seed))
            .collect();
        require(
            matching.len() == 1,
            "actual trace does not select exactly one closed family",
        )?;
        let program = matching[0];
        require(
            !seen[program.family],
            "duplicate complete native family trace",
        )?;
        seen[program.family] = true;
        let view = View {
            prefix,
            draws: trace.draws(),
        };
        let parsed = recognize(program, view)
            .map_err(|e| format!("{} runtime trace: {e}", NAMES[program.family]))?;
        groups += parsed.groups.len();
        samples += parsed.accepted.len();
        attempts += trace.draws().len();
        mutations += reject_mutations(program, view, &parsed)?;
        if let Some(cap) = parsed.pp {
            pp_caps.push((NAMES[program.family], cap));
        }
    }
    require(seen == [true; 5], "missing actual native family trace")?;
    require(
        groups == 77 && samples == 1335 && attempts >= samples,
        "actual five-family totals changed",
    )?;
    require(pp_caps.len() == 3, "missing actual receiver PP CAPs")?;
    eprintln!(
        "hash_read runtime_call_capture=true families=5 groups={groups} samples={samples} attempts={attempts} init_traces={inactive} rejected_mutations={mutations} actual_receiver_pp_caps={pp_caps:?} online_extractor=false adaptive_ROM_proof=false admission=false"
    );
    Ok(())
}
