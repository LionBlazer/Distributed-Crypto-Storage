//! Analysis-only canonical full-prefix history restoration over actual SHA512.
//!
//! This is not a programmable random oracle or a native acceptance interface.
//! Every complete group is assigned from its immutable full-byte ancestor before
//! looking at the target query's answer. Merkle words and the complete public
//! source association are frozen before the relevant group is restored.
use super::*;
use std::ops::ControlFlow;

mod tests;

const SAMPLE: u8 = 3;
const OPENINGS: [usize; 5] = [14502, 3492, 2622, 3024, 2327];
const AUX: [usize; 5] = [0, 0, 410, 175, 420];
const CHUNKS: [usize; 5] = [16, 16, 8, 8, 8];
const MAX_GROUPS: usize = 1024;
const MAX_WORDS: usize = 1024;
const MAX_ANCHOR_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
enum Role {
    Main,
    Pp,
    Aux,
    Quotient,
    Random,
    Fri(usize),
}

/// One fixed equal-height partition per commit, preserving all matrix/salt cuts.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct WordSchema {
    family: usize,
    role: Role,
    depth: usize,
    // Base-field widths INCLUDING hiding codewords, EXCLUDING each salt4.
    widths: Vec<usize>,
}
impl WordSchema {
    fn new(family: usize, role: Role) -> Self {
        let lde = K[family].ilog2() as usize + 3;
        let (depth, widths) = match role {
            Role::Main => (lde, vec![MAIN[family] + 5]),
            Role::Pp => (lde, vec![PP[family]]),
            Role::Aux => (lde, vec![AUX[family] + 5]),
            Role::Quotient => (lde, vec![10; CHUNKS[family]]),
            Role::Random => (lde, vec![10]),
            Role::Fri(round) => (lde - round - 1, vec![10]),
        };
        Self {
            family,
            role,
            depth,
            widths,
        }
    }
    fn salted_fields(&self) -> usize {
        self.widths.iter().map(|width| width + 4).sum()
    }
}

#[derive(Debug)]
struct Word {
    schema: WordSchema,
    root: [u8; 32],
    cutoff: u64,
    // MAIN/PP use the EXACT existing first snapshot, including its Arc identity.
    initial: Option<Arc<Frozen>>,
}
impl Word {
    /// Actual zero-completed immutable row oracle, not just a claimed root.
    /// Later dictionary discoveries are filtered at the first notification cut.
    fn field(&self, dictionary: &Dictionary, row: usize, matrix: usize, column: usize) -> u64 {
        assert!(row < 1 << self.schema.depth);
        assert!(matrix < self.schema.widths.len() && column < self.schema.widths[matrix]);
        if let Some(initial) = &self.initial {
            return initial.field(row, column);
        }
        let mut root = self.root;
        for level in (1..=self.schema.depth).rev() {
            let Some((_, raw)) = dictionary
                .by_output
                .get(&root)
                .filter(|(cut, _)| *cut <= self.cutoff)
            else {
                return 0;
            };
            if raw.len() != suite::NODE_DOMAIN.len() + 64 || !raw.starts_with(suite::NODE_DOMAIN) {
                return 0;
            }
            let at = suite::NODE_DOMAIN.len() + ((row >> (level - 1)) & 1) * 32;
            root = raw[at..at + 32].try_into().expect("fixed node child");
        }
        let Some((_, raw)) = dictionary
            .by_output
            .get(&root)
            .filter(|(cut, _)| *cut <= self.cutoff)
        else {
            return 0;
        };
        if !canonical_leaf(raw, self.schema.salted_fields()) {
            return 0;
        }
        let previous: usize = self.schema.widths[..matrix]
            .iter()
            .map(|width| width + 4)
            .sum();
        let at = suite::LEAF_DOMAIN.len() + (previous + column) * 8;
        u64::from_le_bytes(raw[at..at + 8].try_into().expect("checked canonical leaf"))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Lookup,
    Alpha,
    Zeta,
    Theta,
    Fold(usize),
    Indices,
}

#[derive(Debug)]
struct Group {
    family: usize,
    phase: Phase,
    first_counter: u64,
    values: Vec<u64>,
    retries: Vec<u64>,
    digests: Vec<[u8; 64]>,
    // Fixed BEFORE this group's first actual SHA evaluation; never a verdict.
    words: Vec<Arc<Word>>,
    association: Result<()>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Eligibility {
    // A rejection attempt that precedes the native first accepted candidate.
    Rejected,
    Accepted,
    // Raw ROM queries remain allowed; native rejection_sample cannot visit it.
    AfterAcceptance,
}
fn eligibility(retry: u64, accepted_retry: u64) -> Eligibility {
    match retry.cmp(&accepted_retry) {
        std::cmp::Ordering::Less => Eligibility::Rejected,
        std::cmp::Ordering::Equal => Eligibility::Accepted,
        std::cmp::Ordering::Greater => Eligibility::AfterAcceptance,
    }
}

#[derive(Debug)]
struct Target {
    group: Arc<Group>,
    coordinate: usize,
    retry: u64,
    eligibility: Eligibility,
}

#[derive(Debug)]
struct Reply {
    digest: [u8; 64],
    history: Result<Target>,
}

#[derive(Clone, Copy)]
struct Before<'a> {
    family: usize,
    words: &'a [Arc<Word>],
    association: Result<()>,
}

#[derive(Default)]
struct FullDriver {
    first: Driver,
    // One owner / one SHA256 dictionary / one first typed-word bank for ALL roles.
    words: HashMap<(WordSchema, [u8; 32]), Arc<Word>>,
    // Keys are COMPLETE byte prefixes at the BEGINNING of groups. Counter alone,
    // a digest, a caller family or an Expected never identifies an ancestor.
    groups: HashMap<Arc<[u8]>, Arc<Group>>,
    anchor_bytes: usize,
    restored_draws: usize,
    external_queries: usize,
}
impl FullDriver {
    fn sha256(&mut self, raw: &[u8]) -> [u8; 32] {
        self.first.sha256(raw)
    }
    fn word(
        &mut self,
        schema: WordSchema,
        root: [u8; 32],
        initial: Option<Arc<Frozen>>,
    ) -> Result<Arc<Word>> {
        self.first.dictionary.targets.insert(root);
        if let Some(word) = self.words.get(&(schema.clone(), root)) {
            return Ok(word.clone());
        }
        if self.words.len() >= MAX_WORDS {
            return Err("typed-word-resource-bound");
        }
        let cutoff = initial
            .as_ref()
            .map_or(self.first.dictionary.serial, |word| word.cutoff);
        let word = Arc::new(Word {
            schema: schema.clone(),
            root,
            cutoff,
            initial,
        });
        self.words.insert((schema, root), word.clone());
        Ok(word)
    }
    fn cap(
        &mut self,
        parser: &mut Parser<'_>,
        family: usize,
        role: Role,
        words: &mut Vec<Arc<Word>>,
    ) -> Result<()> {
        let root = parser.cap()?;
        words.push(self.word(WordSchema::new(family, role), root, None)?);
        Ok(())
    }
    fn restore(
        &mut self,
        raw: &[u8],
        phase: Phase,
        counter: u64,
        count: usize,
        before: Before<'_>,
    ) -> Result<Arc<Group>> {
        let Before {
            family,
            words,
            association,
        } = before;
        if let Some(group) = self.groups.get(raw) {
            assert_eq!(
                (
                    group.family,
                    group.phase,
                    group.first_counter,
                    group.values.len()
                ),
                (family, phase, counter, count)
            );
            assert_eq!(group.association, association);
            assert_eq!(group.words.len(), words.len());
            assert!(
                group
                    .words
                    .iter()
                    .zip(words)
                    .all(|(a, b)| Arc::ptr_eq(a, b))
            );
            return Ok(group.clone());
        }
        let next = self
            .anchor_bytes
            .checked_add(raw.len())
            .ok_or("group-resource-bound")?;
        if self.groups.len() >= MAX_GROUPS || next > MAX_ANCHOR_BYTES {
            return Err("group-resource-bound");
        }
        // No target hash has been evaluated yet. Entire vector and all of its
        // prior word identities are assigned even if coordinate192 arrives first.
        let mut state = Sha512::new();
        state.update(raw);
        let mut values = Vec::with_capacity(count);
        let mut retries = Vec::with_capacity(count);
        let mut digests = Vec::with_capacity(count);
        for coordinate in 0..count {
            let counter = counter
                .checked_add(coordinate as u64)
                .ok_or("counter-overflow")?;
            let mut retry = 0u64;
            let (value, digest) = loop {
                let mut draw = state.clone();
                draw.update([DRAW]);
                draw.update(counter.to_le_bytes());
                draw.update(retry.to_le_bytes());
                let digest: [u8; 64] = draw.finalize().into();
                self.restored_draws = self
                    .restored_draws
                    .checked_add(1)
                    .ok_or("draw-accounting-overflow")?;
                let value = u64::from_le_bytes(digest[..8].try_into().expect("digest8"));
                if value < Val::ORDER_U64 {
                    break (value, digest);
                }
                retry = retry.checked_add(1).ok_or("retry-overflow")?;
            };
            values.push(value);
            retries.push(retry);
            digests.push(digest);
            state.update([SAMPLE]);
            state.update(counter.to_le_bytes());
            state.update(value.to_le_bytes());
        }
        let group = Arc::new(Group {
            family,
            phase,
            first_counter: counter,
            values,
            retries,
            digests,
            words: words.to_vec(),
            association,
        });
        self.groups.insert(Arc::from(raw), group.clone());
        self.anchor_bytes = next;
        Ok(group)
    }
    fn group(
        &mut self,
        parser: &mut Parser<'_>,
        phase: Phase,
        counter: &mut u64,
        count: usize,
        before: Before<'_>,
    ) -> Result<ControlFlow<Target>> {
        let group = self.restore(&parser.raw[..parser.at], phase, *counter, count, before)?;
        for coordinate in 0..count {
            if parser.raw.get(parser.at) == Some(&DRAW) {
                parser.take(1)?;
                let claimed = u64::from_le_bytes(parser.take(8)?.try_into().expect("counter8"));
                let retry = u64::from_le_bytes(parser.take(8)?.try_into().expect("retry8"));
                if claimed != *counter || parser.at != parser.raw.len() {
                    return Err("DRAW-counter-or-EOF");
                }
                let eligibility = eligibility(retry, group.retries[coordinate]);
                return Ok(ControlFlow::Break(Target {
                    group,
                    coordinate,
                    retry,
                    eligibility,
                }));
            }
            if parser.take(1)? != [SAMPLE] {
                return Err("SAMPLE-tag");
            }
            let claimed = u64::from_le_bytes(parser.take(8)?.try_into().expect("counter8"));
            let value = u64::from_le_bytes(parser.take(8)?.try_into().expect("value8"));
            if claimed != *counter || value >= Val::ORDER_U64 || value != group.values[coordinate] {
                return Err("noncanonical-or-false-SAMPLE-ancestor");
            }
            *counter = counter.checked_add(1).ok_or("counter-overflow")?;
        }
        Ok(ControlFlow::Continue(()))
    }
    fn inspect(&mut self, raw: &[u8]) -> Result<Target> {
        let initial = initial(raw, &mut self.first.dictionary)?;
        let association = *self
            .first
            .instances
            .entry(raw[..initial.end].to_vec())
            .or_insert_with(|| read_before_first_coin(&mut Input::new(&initial)).map(|_| ()));
        let family = initial.family;
        let mut words = vec![self.word(
            WordSchema::new(family, Role::Main),
            initial.main.root,
            Some(initial.main.clone()),
        )?];
        if let Some(pp) = &initial.pp {
            words.push(self.word(WordSchema::new(family, Role::Pp), pp.root, Some(pp.clone()))?);
        }
        let mut parser = Parser {
            raw,
            at: initial.end,
        };
        let mut counter = 0;
        macro_rules! group {
            ($phase:expr, $count:expr) => {
                if let ControlFlow::Break(target) = self.group(
                    &mut parser,
                    $phase,
                    &mut counter,
                    $count,
                    Before {
                        family,
                        words: &words,
                        association,
                    },
                )? {
                    return Ok(target);
                }
            };
        }
        if family >= 2 {
            group!(Phase::Lookup, 10);
            self.cap(&mut parser, family, Role::Aux, &mut words)?;
            for _ in 0..5 {
                if parser.field()? != Val::ZERO {
                    return Err("terminal-must-be-zero");
                }
            }
        }
        group!(Phase::Alpha, 5);
        self.cap(&mut parser, family, Role::Quotient, &mut words)?;
        self.cap(&mut parser, family, Role::Random, &mut words)?;
        group!(Phase::Zeta, 5);
        exact(&mut parser, &pcs_seed(family))?;
        for _ in 0..OPENINGS[family] * 5 {
            let _ = parser.field()?;
        }
        group!(Phase::Theta, 5);
        exact(&mut parser, &fri_seed(family))?;
        for round in 0..K[family].ilog2() as usize {
            self.cap(&mut parser, family, Role::Fri(round), &mut words)?;
            group!(Phase::Fold(round), 5);
        }
        for _ in 0..5 {
            let _ = parser.field()?;
        }
        group!(Phase::Indices, 192);
        Err("complete-transcript-is-not-a-DRAW-query")
    }
    fn sha512(&mut self, raw: &[u8]) -> Reply {
        self.external_queries += 1;
        let history = self.inspect(raw);
        // All malformed/raw/post-acceptance queries get actual SHA512 answers.
        // No classification or ancestor failure repairs a previously seen input.
        let digest = Sha512::digest(raw).into();
        if let Ok(target) = &history
            && target.eligibility == Eligibility::Accepted
        {
            assert_eq!(digest, target.group.digests[target.coordinate]);
        }
        Reply { digest, history }
    }
}

fn exact(parser: &mut Parser<'_>, bytes: &[u8]) -> Result<()> {
    if parser.take(bytes.len())? == bytes {
        Ok(())
    } else {
        Err("nested-native-seed")
    }
}
fn encoded_seed(
    separator: &p3_challenger::fs::DomainSeparator<p3_challenger::fs::FieldUnit<Val>>,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    for field in inspect_separator(separator).observed_fields() {
        bytes.push(FIELD);
        bytes.extend(field.as_canonical_u64().to_le_bytes());
    }
    bytes
}
fn pcs_shape(family: usize) -> p3_fri::PcsShape {
    let matrix = |width, points| vec![width; points];
    let mut claims = vec![
        vec![matrix(10, 1)],
        vec![matrix(MAIN[family] + 5, 2)],
        vec![matrix(10, 1); CHUNKS[family]],
    ];
    if family >= 2 {
        claims.push(vec![matrix(PP[family], if family == 3 { 2 } else { 1 })]);
        claims.push(vec![matrix(AUX[family] + 5, 2)]);
    }
    p3_fri::PcsShape {
        claimed_evaluation_counts: claims,
        batch_pow_bits: 0,
    }
}
fn pcs_seed(family: usize) -> Vec<u8> {
    encoded_seed(&pcs_shape(family).domain_separator::<Val, Challenge>())
}
fn fri_shape(family: usize) -> p3_fri::FriShape {
    p3_fri::FriShape {
        log_arities: vec![1; K[family].ilog2() as usize],
        final_poly_len: 1,
        commit_pow_bits: 0,
        query_pow_bits: 0,
        num_queries: 192,
        index_bits: K[family].ilog2() as usize + 3,
        log_blowup: 3,
        max_log_arity: 1,
    }
}
fn fri_seed(family: usize) -> Vec<u8> {
    encoded_seed(&fri_shape(family).domain_separator::<Val, Challenge>())
}

/// Additional analysis of ALREADY captured genuine native receiving calls.
/// No Expected, proof production, verifier callback or acceptance authority.
/// The empty dictionary intentionally cannot authenticate unseen public PP.
pub(in crate::registry_progress) fn check_actual_histories(
    traces: &[suite::audit::Trace],
) -> Result<()> {
    const SAMPLES: [usize; 5] = [257, 257, 277, 267, 277];
    const GROUPS: [usize; 5] = [14, 14, 17, 15, 17];
    fn raw(trace: &suite::audit::Trace, draw: &suite::audit::Draw) -> Vec<u8> {
        let mut bytes = trace.prefix()[..draw.prefix_len()].to_vec();
        bytes.push(DRAW);
        bytes.extend(draw.counter().to_le_bytes());
        bytes.extend(draw.retry().to_le_bytes());
        bytes
    }
    if traces.len() > 64 {
        return Err("native-history-trace-cap");
    }
    // Check EVERY inactive constructor/fork before filtering it out.
    for trace in traces {
        if trace.draws().is_empty() {
            if trace.prefix() != DOMAIN {
                return Err("native-history-inactive-prefix");
            }
        } else if !trace.prefix().starts_with(DOMAIN)
            || trace.prefix().len() > 8 * 1024 * 1024
            || trace.draws().len() > 4096
            || trace
                .draws()
                .iter()
                .any(|draw| draw.prefix_len() > trace.prefix().len())
        {
            return Err("native-history-active-extent");
        }
    }
    let mut active = Vec::new();
    let mut seen = [false; 5];
    for trace in traces.iter().filter(|trace| !trace.draws().is_empty()) {
        let tail = &trace.prefix()[DOMAIN.len()..];
        let matching = (0..5)
            .filter(|&family| tail.starts_with(&seed(family)))
            .collect::<Vec<_>>();
        if matching.len() != 1 || seen[matching[0]] {
            return Err("native-history-family");
        }
        seen[matching[0]] = true;
        active.push((matching[0], trace));
    }
    if seen != [true; 5] {
        return Err("native-history-missing-family");
    }

    let mut driver = FullDriver::default();
    let mut accepted = core::array::from_fn::<_, 5, _>(|family| vec![false; SAMPLES[family]]);
    let mut targets = HashMap::new();
    let mut attempts = 0usize;
    // Reverse the ENTIRE captured query collection, not only each group.
    // The last index coordinate is examined before any explicit ancestor query.
    for &(family, trace) in active.iter().rev() {
        for draw in trace.draws().iter().rev() {
            let reply = driver.sha512(&raw(trace, draw));
            if &reply.digest != draw.digest() {
                return Err("native-history-actual-digest");
            }
            let target = reply.history?;
            if target.group.family != family
                || target
                    .group
                    .first_counter
                    .checked_add(target.coordinate as u64)
                    != Some(draw.counter())
                || target.retry != draw.retry()
            {
                return Err("native-history-counter-family");
            }
            let value = u64::from_le_bytes(draw.digest()[..8].try_into().expect("digest8"));
            let expected = if value < Val::ORDER_U64 {
                Eligibility::Accepted
            } else {
                Eligibility::Rejected
            };
            if target.eligibility != expected {
                return Err("native-history-attempt-eligibility");
            }
            if expected == Eligibility::Accepted {
                let counter =
                    usize::try_from(draw.counter()).map_err(|_| "native-history-counter")?;
                let bit = accepted[family]
                    .get_mut(counter)
                    .ok_or("native-history-counter")?;
                if *bit || target.group.values[target.coordinate] != value {
                    return Err("native-history-accepted-value");
                }
                *bit = true;
            }
            // No SHA256 tree queries were supplied. Word's fixed PP must FAIL
            // association. DATA/Query's arbitrary-field zero fallback may pass
            // their source factory but is NOT authenticated receiver-owned PP.
            let association = if family == 3 {
                Err("Word-PP-differs-from-genuine-fixed-factory")
            } else {
                Ok(())
            };
            if target.group.association != association {
                return Err("native-history-source-association");
            }
            let key = (family, draw.counter(), draw.retry());
            if targets
                .insert(key, (target.group, target.coordinate, target.eligibility))
                .is_some()
            {
                return Err("native-history-duplicate-attempt");
            }
            attempts += 1;
        }
    }
    if accepted.iter().any(|family| family.iter().any(|bit| !bit)) {
        return Err("native-history-accepted-count");
    }
    let sample_count: usize = driver.groups.values().map(|group| group.values.len()).sum();
    if driver.groups.len() != 77
        || sample_count != 1335
        || driver.words.len() != 75
        || driver
            .words
            .keys()
            .filter(|(schema, _)| schema.role == Role::Pp)
            .count()
            != 3
        || driver.first.instances.len() != 5
        || driver.first.dictionary.first.len() != 8
    {
        return Err("native-history-aggregate-counts");
    }
    for (family, count) in GROUPS.into_iter().enumerate() {
        if driver
            .groups
            .values()
            .filter(|group| group.family == family)
            .count()
            != count
        {
            return Err("native-history-family-group-count");
        }
    }
    // Freeze exact Word and MAIN/PP snapshot objects, then grow the shared table
    // once. Replaying all actual raw queries must not re-time a first cutoff.
    let first_words = driver.words.clone();
    let first_snapshots = driver.first.dictionary.first.clone();
    let restored = driver.restored_draws;
    let anchors = driver.anchor_bytes;
    driver.sha256(b"DCS/research/actual-native-full-history/late-unrelated-query/v1");
    for &(family, trace) in &active {
        for draw in trace.draws() {
            let reply = driver.sha512(&raw(trace, draw));
            let target = reply.history?;
            let (first, coordinate, eligible) = targets
                .get(&(family, draw.counter(), draw.retry()))
                .ok_or("native-history-missing-replay")?;
            if &reply.digest != draw.digest()
                || !Arc::ptr_eq(first, &target.group)
                || target.coordinate != *coordinate
                || target.eligibility != *eligible
            {
                return Err("native-history-group-replay");
            }
        }
    }
    if driver.restored_draws != restored
        || driver.anchor_bytes != anchors
        || driver.words.len() != first_words.len()
        || driver.first.dictionary.first.len() != first_snapshots.len()
    {
        return Err("native-history-replay-restored-new-state");
    }
    for (key, first) in first_words {
        let now = driver.words.get(&key).ok_or("native-history-lost-word")?;
        if !Arc::ptr_eq(&first, now) || first.cutoff != now.cutoff {
            return Err("native-history-word-identity");
        }
        if matches!(first.schema.role, Role::Main | Role::Pp) {
            let initial = first
                .initial
                .as_ref()
                .ok_or("native-history-missing-initial")?;
            let stored = first_snapshots
                .get(&(initial.schema, initial.root))
                .ok_or("native-history-snapshot-key")?;
            let now = driver
                .first
                .dictionary
                .first
                .get(&(initial.schema, initial.root))
                .ok_or("native-history-lost-snapshot")?;
            if !Arc::ptr_eq(initial, stored)
                || !Arc::ptr_eq(initial, now)
                || initial.leaves.iter().any(Option::is_some)
            {
                return Err("native-history-first-snapshot-identity");
            }
        }
    }
    eprintln!(
        "hash_read full_history_actual_native_capture=true families=5 groups=77 samples=1335 roots=75 PP=3 reversed_raw_attempts={attempts} replay_same_group_and_snapshot=true complete_PP_extraction=false Word_mu_association=false DATA_Query_PP_authenticated=false unseen_PP_zero_fallback=true admission=false"
    );
    Ok(())
}
