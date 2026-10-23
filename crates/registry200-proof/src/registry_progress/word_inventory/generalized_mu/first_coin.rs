//! Research first-coin source-association harness, never native acceptance.
//!
//! Owns both hash-query registration and synchronous frozen-word classification.
//! Hashes are the actual SHA functions here, not a simulated ROM experiment.
//! Later canonical ancestor/restoration and the quantitative RBR proof are absent.
use super::{DEPTH, K, PP, PUBLIC, Result, read_before_first_coin};
use crate::Val;
use bfv_hiding_stark::{Challenge, hash as suite, transcript::inspect_separator};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use sha2::{Digest, Sha256, Sha512};
use std::{
    collections::{HashMap, HashSet},
    io::{self, Read},
    sync::Arc,
};

mod tests;

const MAIN: [usize; 5] = [7161, 1656, 512, 568, 416];
const DOMAIN: &[u8] = suite::TRANSCRIPT_DOMAIN;
const FIELD: u8 = 1;
const CAP: u8 = 2;
const DRAW: u8 = 4;

fn seed(family: usize) -> Vec<u8> {
    let binding = if family < 2 {
        let shape = uni_shape(family);
        inspect_separator(&shape.domain_separator::<Val, Challenge>())
    } else {
        let shape = batch_shape(family);
        inspect_separator(&shape.domain_separator::<Val, Challenge>())
    };
    let mut bytes = Vec::new();
    for field in binding.observed_fields() {
        bytes.push(FIELD);
        bytes.extend(field.as_canonical_u64().to_le_bytes());
    }
    bytes
}

fn uni_shape(family: usize) -> p3_uni_stark::StarkShape {
    p3_uni_stark::StarkShape {
        log_ext_degree: 10,
        log_degree: 9,
        main_width: MAIN[family],
        preprocessed_width: 0,
        num_public_values: PUBLIC[family],
        num_periodic_columns: 512,
        num_quotient_chunks: 16,
        opens_main_next_row: true,
        opens_preprocessed_next_row: false,
        has_randomization: true,
        ood_pow_bits: 0,
    }
}
fn batch_shape(family: usize) -> p3_batch_stark::BatchShape {
    p3_batch_stark::BatchShape {
        trace_widths: vec![MAIN[family]],
        public_value_counts: vec![PUBLIC[family]],
        preprocessed_widths: vec![PP[family]],
        has_preprocessed_commitment: true,
        num_lookup_instances: 1,
        lookup_pow_bits: 0,
        has_randomization_commitment: true,
        ood_pow_bits: 0,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Schema {
    family: usize,
    pp: bool,
}
impl Schema {
    fn depth(self) -> usize {
        K[self.family].ilog2() as usize + 3
    }
    fn width(self) -> usize {
        if self.pp {
            PP[self.family]
        } else {
            MAIN[self.family] + 5
        }
    }
    fn fields(self) -> usize {
        self.width() + 4
    }
}

#[derive(Debug)]
struct Frozen {
    schema: Schema,
    root: [u8; 32],
    cutoff: u64,
    leaves: Vec<Option<Arc<[u8]>>>,
}
impl Frozen {
    fn field(&self, row: usize, column: usize) -> u64 {
        assert!(row < self.leaves.len() && column < self.schema.width());
        self.leaves[row].as_ref().map_or(0, |raw| {
            let start = suite::LEAF_DOMAIN.len() + 8 * column;
            u64::from_le_bytes(
                raw[start..start + 8]
                    .try_into()
                    .expect("fixed checked field"),
            )
        })
    }
}

#[derive(Default)]
struct Dictionary {
    by_input: HashMap<Arc<[u8]>, [u8; 32]>,
    by_output: HashMap<[u8; 32], (u64, Arc<[u8]>)>,
    first: HashMap<(Schema, [u8; 32]), Arc<Frozen>>,
    targets: HashSet<[u8; 32]>,
    collisions: usize,
    target_hits: usize,
    serial: u64,
}
impl Dictionary {
    fn query(&mut self, raw: &[u8]) -> [u8; 32] {
        if let Some(output) = self.by_input.get(raw) {
            return *output;
        }
        let output: [u8; 32] = Sha256::digest(raw).into();
        self.collisions += usize::from(self.by_output.contains_key(&output));
        self.target_hits += usize::from(self.targets.contains(&output));
        self.serial = self.serial.checked_add(1).expect("finite research trace");
        let raw: Arc<[u8]> = Arc::from(raw);
        self.by_output
            .entry(output)
            .or_insert_with(|| (self.serial, raw.clone()));
        if raw.len() == suite::NODE_DOMAIN.len() + 64 && raw.starts_with(suite::NODE_DOMAIN) {
            let at = suite::NODE_DOMAIN.len();
            self.targets
                .insert(raw[at..at + 32].try_into().expect("left target"));
            self.targets
                .insert(raw[at + 32..].try_into().expect("right target"));
        }
        self.by_input.insert(raw, output);
        output
    }
    fn notify(&mut self, schema: Schema, root: [u8; 32]) -> Arc<Frozen> {
        self.targets.insert(root);
        if let Some(first) = self.first.get(&(schema, root)) {
            return first.clone();
        }
        let mut leaves = Vec::with_capacity(1 << schema.depth());
        self.walk(schema, root, schema.depth(), self.serial, &mut leaves);
        let frozen = Arc::new(Frozen {
            schema,
            root,
            cutoff: self.serial,
            leaves,
        });
        self.first.insert((schema, root), frozen.clone());
        frozen
    }
    fn walk(
        &self,
        schema: Schema,
        root: [u8; 32],
        depth: usize,
        cutoff: u64,
        leaves: &mut Vec<Option<Arc<[u8]>>>,
    ) {
        let raw = self
            .by_output
            .get(&root)
            .filter(|(serial, _)| *serial <= cutoff)
            .map(|(_, raw)| raw);
        if depth == 0 {
            leaves.push(
                raw.filter(|raw| canonical_leaf(raw, schema.fields()))
                    .cloned(),
            );
        } else if let Some(raw) = raw.filter(|raw| {
            raw.len() == suite::NODE_DOMAIN.len() + 64 && raw.starts_with(suite::NODE_DOMAIN)
        }) {
            let start = suite::NODE_DOMAIN.len();
            self.walk(
                schema,
                raw[start..start + 32].try_into().expect("left"),
                depth - 1,
                cutoff,
                leaves,
            );
            self.walk(
                schema,
                raw[start + 32..].try_into().expect("right"),
                depth - 1,
                cutoff,
                leaves,
            );
        } else {
            leaves.resize(leaves.len() + (1 << depth), None);
        }
    }
}

fn canonical_leaf(raw: &[u8], fields: usize) -> bool {
    raw.len() == suite::LEAF_DOMAIN.len() + fields * 8 + 8
        && raw.starts_with(suite::LEAF_DOMAIN)
        && raw[raw.len() - 8..] == (fields as u64).to_le_bytes()
        && raw[suite::LEAF_DOMAIN.len()..raw.len() - 8]
            .as_chunks::<8>()
            .0
            .iter()
            .all(|bytes| u64::from_le_bytes(*bytes) < Val::ORDER_U64)
}

struct Initial {
    family: usize,
    public: Vec<Val>,
    main: Arc<Frozen>,
    pp: Option<Arc<Frozen>>,
    end: usize,
}

struct Parser<'a> {
    raw: &'a [u8],
    at: usize,
}
impl Parser<'_> {
    fn take(&mut self, count: usize) -> Result<&[u8]> {
        let end = self.at.checked_add(count).ok_or("raw-extent")?;
        let bytes = self
            .raw
            .get(self.at..end)
            .ok_or("incomplete-initial-prefix")?;
        self.at = end;
        Ok(bytes)
    }
    fn field(&mut self) -> Result<Val> {
        if self.take(1)? != [FIELD] {
            return Err("FIELD-tag");
        }
        let value = u64::from_le_bytes(self.take(8)?.try_into().map_err(|_| "FIELD")?);
        if value >= Val::ORDER_U64 {
            return Err("canonical-FIELD");
        }
        Ok(Val::from_u64(value))
    }
    fn cap(&mut self) -> Result<[u8; 32]> {
        if self.take(1)? != [CAP] || self.take(8)? != 1u64.to_le_bytes() {
            return Err("one-root-CAP");
        }
        self.take(32)?.try_into().map_err(|_| "CAP-root")
    }
}

/// MAIN notification occurs immediately at its parsed extent, even if later u
/// is missing or malformed. PP notification likewise precedes any tail parsing.
fn initial(raw: &[u8], dictionary: &mut Dictionary) -> Result<Initial> {
    // Only the fixed-size initial grammar is inspected. A large unrelated
    // suffix must not defer a valid initial word's first notification.
    if !raw.starts_with(DOMAIN) {
        return Err("raw-domain");
    }
    let candidates = (0..5)
        .filter(|&family| raw[DOMAIN.len()..].starts_with(&seed(family)))
        .collect::<Vec<_>>();
    if candidates.len() != 1 {
        return Err("unique-native-seed");
    }
    let family = candidates[0];
    let mut parser = Parser {
        raw,
        at: DOMAIN.len() + seed(family).len(),
    };
    if family >= 2 {
        for expected in [
            Val::from_usize(K[family].ilog2() as usize),
            Val::ZERO,
            Val::ZERO,
            Val::ZERO,
            Val::ZERO,
        ] {
            if parser.field()? != expected {
                return Err("fixed-degree-EF5");
            }
        }
    }
    let root = parser.cap()?;
    let main = dictionary.notify(Schema { family, pp: false }, root);
    let public = (0..PUBLIC[family])
        .map(|_| parser.field())
        .collect::<Result<Vec<_>>>()?;
    let pp = if PP[family] != 0 {
        let root = parser.cap()?;
        Some(dictionary.notify(Schema { family, pp: true }, root))
    } else {
        None
    };
    Ok(Initial {
        family,
        public,
        main,
        pp,
        end: parser.at,
    })
}

/// A private source-classifier stream. Roots and cutoffs are copied ONLY from
/// this driver's registered first snapshots, never from a caller file/header.
struct Input<'a> {
    prefix: Vec<u8>,
    pp: Option<&'a Frozen>,
    at: usize,
}
impl<'a> Input<'a> {
    fn new(initial: &'a Initial) -> Self {
        let mut prefix = [0; 64].to_vec();
        prefix[..8].copy_from_slice(b"DCSMUB01");
        prefix[8] = initial.family as u8;
        if let Some(pp) = &initial.pp {
            prefix[9] = DEPTH[initial.family];
            prefix[16..48].copy_from_slice(&pp.root);
            prefix[48..56].copy_from_slice(&pp.cutoff.to_le_bytes());
        }
        for field in &initial.public {
            prefix.extend(field.as_canonical_u64().to_le_bytes());
        }
        Self {
            prefix,
            pp: initial.pp.as_deref(),
            at: 0,
        }
    }
}
impl Read for Input<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = self.pp.map_or(0, |pp| pp.schema.width() * pp.leaves.len());
        let extent = self.prefix.len() + count * 8;
        let size = output.len().min(extent - self.at);
        for (index, byte) in output.iter_mut().take(size).enumerate() {
            let at = self.at + index;
            *byte = if let Some(value) = self.prefix.get(at) {
                *value
            } else {
                let pp = self.pp.expect("nonempty PP payload");
                let cell = (at - self.prefix.len()) / 8;
                pp.field(cell % pp.leaves.len(), cell / pp.leaves.len())
                    .to_le_bytes()[(at - self.prefix.len()) % 8]
            };
        }
        self.at += size;
        Ok(size)
    }
}

#[derive(Debug)]
struct Reply {
    digest: [u8; 64],
    first_draw: Option<(usize, u64)>,
    association: Option<Result<()>>,
}

#[derive(Default)]
struct Driver {
    dictionary: Dictionary,
    // Key is the COMPLETE initial event prefix, not just PV, cap or a digest.
    instances: HashMap<Vec<u8>, Result<()>>,
    closed_before_hash: usize,
}
impl Driver {
    fn sha256(&mut self, raw: &[u8]) -> [u8; 32] {
        self.dictionary.query(raw)
    }
    fn sha512(&mut self, raw: &[u8]) -> Reply {
        let mut first_draw = None;
        let association = initial(raw, &mut self.dictionary).ok().map(|initial| {
            let key = raw[..initial.end].to_vec();
            let result = *self
                .instances
                .entry(key)
                .or_insert_with(|| read_before_first_coin(&mut Input::new(&initial)).map(|_| ()));
            // This checks snapshot IDENTITY, not a caller's claimed cutoff.
            assert!(Arc::ptr_eq(
                &initial.main,
                self.dictionary
                    .first
                    .get(&(initial.main.schema, initial.main.root))
                    .expect("registered MAIN")
            ));
            if let Some(pp) = &initial.pp {
                assert!(Arc::ptr_eq(
                    pp,
                    self.dictionary
                        .first
                        .get(&(pp.schema, pp.root))
                        .expect("registered PP")
                ));
            }
            let tail = &raw[initial.end..];
            if tail.len() == 17 && tail[0] == DRAW && tail[1..9] == 0u64.to_le_bytes() {
                first_draw = Some((
                    initial.family,
                    u64::from_le_bytes(tail[9..17].try_into().expect("retry8")),
                ));
            }
            self.closed_before_hash += 1;
            result
        });
        // Every raw query still receives the actual consistent hash, including
        // invalid/malformed/non-first/reverse-retry inputs. No failed prefix is
        // repaired or reclassified on later dictionary or Expected discovery.
        let digest = Sha512::digest(raw).into();
        Reply {
            digest,
            first_draw,
            association,
        }
    }
}
