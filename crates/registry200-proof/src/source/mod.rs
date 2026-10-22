//! Fixed PUBLIC source-opening claims and the one shared AEAD/canonical circuit.
//! This low-level namespace exposes mathematical claims, not admission tokens.
pub mod air;
pub mod canonical;
pub mod chacha;
pub mod circuit;
pub mod commitment;
pub mod factorized;
pub mod hash;
pub mod layout;
pub mod poly1305;
mod prover;
pub(crate) mod verification;
pub mod version;
pub use prover::{SourceEvidence, prove};
pub mod schedule;
pub mod statement;
pub use bfv_hiding_stark::poseidon;
use sha2::{Digest, Sha256};
pub use statement::Statement;
pub const DATA_BYTES: usize = 12;
pub const INDEX_BYTES: usize = 2336;
pub const PLAINTEXT_WORDS: usize = 587;
pub const KEY_DOMAIN: [u8; 16] = *b"DCS/KEY/PAIR/v1!";
pub const OPEN_DOMAIN: [u8; 16] = *b"DCS/OPEN/PAIR/v1";
pub const VERSION: u32 = 1;
pub const DATA_SCHEMA: [u8; 16] = *b"CQAGEAMOUNT00001";
pub const INDEX_SCHEMA: [u8; 16] = *b"CQAGEINDEX000003";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Relation {
    Bytes,
    CanonicalIndex,
    PackedCanonicalIndex,
    FactorizedPackedCanonicalIndex,
    StateCertificate,
}
impl Relation {
    pub fn kind_name(self) -> &'static str {
        match self {
            Self::Bytes => "pair-opening",
            Self::CanonicalIndex => "canonical-index-opening",
            Self::PackedCanonicalIndex => "packed-canonical-index-opening",
            Self::FactorizedPackedCanonicalIndex => "factorized-packed-canonical-index-opening",
            Self::StateCertificate => "state-certificate",
        }
    }
    pub fn packed(self) -> bool {
        matches!(
            self,
            Self::PackedCanonicalIndex
                | Self::FactorizedPackedCanonicalIndex
                | Self::StateCertificate
        )
    }
    pub fn factorized(self) -> bool {
        matches!(self, Self::FactorizedPackedCanonicalIndex)
    }
    pub fn is_canonical(self) -> bool {
        !matches!(self, Self::Bytes)
    }
    pub fn width(self) -> usize {
        match self {
            Self::Bytes => air::WIDTH,
            Self::CanonicalIndex => canonical::WIDTH,
            Self::PackedCanonicalIndex
            | Self::FactorizedPackedCanonicalIndex
            | Self::StateCertificate => layout::PACKED_WIDTH,
        }
    }
}

/// Distinct unreleased relation; the original profile byte strings remain untouched.
pub fn packed_index_profile(hash: &mut sha2::Sha256) {
    use sha2::Digest;
    hash.update(b"CSTORE-canonical-age-index-N4/packed-u32-v1/no-SQL-acceptance");
    hash.update(KEY_DOMAIN);
    hash.update(OPEN_DOMAIN);
    hash.update(DATA_SCHEMA);
    hash.update(INDEX_SCHEMA);
    hash.update(b"same-K-both-pages/AAD106/padded-full-hibit/LE-source-u32/salts4+4");
    hash.update(b"Cha7x82x6/QR0..79/final80/NEXT-feedforward-bits81/CURRENT-capture81/resetNEXT82");
    hash.update(b"plaintext112-u32/immutable-K8-SK16-PK16/selected-PK-view256/raw-clamp-unchanged");
    hash.update(poly1305::CLAMP);
    hash.update(b"one-byte-postings/padding8/histogram256/offsets257/sorted-age-ordinal4");
    hash.update(b"TableId-two-u32sum-halves/ID-u32sum-nonzero/6pairs-8wordzero-inverse-count");
    hash.update(b"P2-native12/overwrite8-cap4/x7-cube/4full22partial4full/key32/open680");
    let c = layout::Columns::new(true);
    let ci = layout::CanonicalColumns::new(true);
    for value in [
        VERSION as usize,
        DATA_BYTES,
        INDEX_BYTES,
        PLAINTEXT_WORDS,
        691,
        c.buffers,
        c.banks,
        c.master,
        c.subkey,
        c.polykey,
        c.polykey_bits,
        c.poly,
        c.poseidon,
        c.checkpoint,
        c.carry,
        c.salts,
        c.width,
        ci.ages,
        ci.permutation,
        ci.sort,
        ci.header,
        ci.identity,
        ci.table_half,
        ci.width,
        512,
        82,
        80,
        81,
        42,
        163,
        2196,
        2208,
        2336,
        4,
        8,
        32,
        5,
    ] {
        hash.update((value as u64).to_le_bytes());
    }
    let schedule = schedule::Schedule::new(true);
    for row in 0..512 {
        hash.update((row as u64).to_le_bytes());
        match schedule.absorb(row) {
            Some((key, block)) => {
                hash.update([1, u8::from(key)]);
                hash.update((block as u64).to_le_bytes());
            }
            None => hash.update([0, 0]),
        }
        match schedule::mac(row) {
            schedule::Mac::Block { page, block } => {
                hash.update([1, page as u8]);
                hash.update((block as u64).to_le_bytes());
            }
            schedule::Mac::Final(page) => hash.update([2, page as u8]),
            schedule::Mac::Idle => hash.update([0, 0]),
        }
    }
    for index in 0..42 {
        match schedule::job(index) {
            schedule::Job::H(page) => hash.update([0, page as u8]),
            schedule::Job::Cha { page, counter } => {
                hash.update([1, page as u8]);
                hash.update(counter.to_le_bytes());
            }
        }
    }
    for indices in chacha::SCHEDULE {
        for index in indices {
            hash.update((index as u64).to_le_bytes());
        }
    }
    for word in chacha::CONSTANTS {
        hash.update(word.to_le_bytes());
    }
    for word in chacha::HCHACHA_OUTPUT {
        hash.update((word as u64).to_le_bytes());
    }
    for row in schedule.captures() {
        hash.update((row as u64).to_le_bytes());
    }
}

pub fn index_profile(hash: &mut sha2::Sha256) {
    use sha2::Digest;
    profile(hash);
    hash.update(b"CSTORE-canonical-age-index-N4/experimental-v1/no-SQL-acceptance");
    hash.update(b"index-v3/header2196/capacity8/aligned2208/total2336");
    hash.update(b"all-counts256/all-prefix-offsets257/sorted-age-ordinal-permutation4");
    hash.update(b"canonical-one-byte-postings4/padding8/nonzero-TableId/distinct-nonzero-RowIds4");
    hash.update(b"ages-constant-all-rows/bind80/TableId-half-capture80-NEXT-skip/check161/IDs485");
    hash.update(b"header-exact-existing-P2-stream-slots/no-global-identity-or-history-claim");
    for value in [
        canonical::WIDTH,
        canonical::WIDTH - air::WIDTH,
        442,
        4,
        32,
        256,
        257,
    ] {
        hash.update((value as u64).to_le_bytes());
    }
}

/// Pins the candidate construction, constants, geometry and complete public schedule.
/// This is an unreleased experiment profile, not the production BFV/kernel profile.
pub fn profile(hash: &mut sha2::Sha256) {
    use sha2::Digest;
    hash.update(b"CSTORE-whole-pair-byte-opening/experimental-v1/no-SQL-acceptance");
    hash.update(KEY_DOMAIN);
    hash.update(OPEN_DOMAIN);
    hash.update(VERSION.to_le_bytes());
    hash.update(DATA_SCHEMA);
    hash.update(INDEX_SCHEMA);
    hash.update(b"source-u32LE/commitment-canonical-u64LE/key26+6/open674+6/87prefix");
    hash.update(b"P2-native12-initialMDS-4full-22partial-4full/x7-cube/overwrite8-cap4-digest4");
    hash.update(b"same-K-both-pages/packet-revision-AAD106/full-padded-hibit/raw-private-salts4+4");
    hash.update(b"Cha7x81x6/immutable-K-SK-PK/boundary-CURRENT/skip-NEXT-boundary-copy");
    hash.update(b"carry-CURRENT/skip-NEXT-capture-copy/reset-sponge-capacity/embedded-head28");
    for n in [
        DATA_BYTES,
        INDEX_BYTES,
        PLAINTEXT_WORDS,
        691,
        air::WIDTH,
        512,
        3,
        256,
        4096,
        4,
        26,
        32,
        674,
        680,
        87,
        5, // conservative declaration; actual composed inference is a later gate
    ] {
        hash.update((n as u64).to_le_bytes());
    }
    for row in 0..512 {
        hash.update((row as u64).to_le_bytes());
        match schedule::absorb(row) {
            Some((key, block)) => {
                hash.update([1, u8::from(key)]);
                hash.update((block as u64).to_le_bytes());
            }
            None => hash.update([0, 0]),
        }
        match schedule::mac(row) {
            schedule::Mac::Block { page, block } => {
                hash.update([1, page as u8]);
                hash.update((block as u64).to_le_bytes());
            }
            schedule::Mac::Final(page) => hash.update([2, page as u8]),
            schedule::Mac::Idle => hash.update([0, 0]),
        }
    }
    for index in 0..42 {
        match schedule::job(index) {
            schedule::Job::H(page) => hash.update([0, page as u8]),
            schedule::Job::Cha { page, counter } => {
                hash.update([1, page as u8]);
                hash.update(counter.to_le_bytes());
            }
        }
    }
    for indices in chacha::SCHEDULE {
        for index in indices {
            hash.update((index as u64).to_le_bytes());
        }
    }
    for row in schedule::CAPTURES {
        hash.update((row as u64).to_le_bytes());
    }
}

pub const STATE_DOMAIN: [u8; 16] = *b"DCS/STATE/N4/v1!";
pub fn certificate_profile(hash: &mut Sha256) {
    hash.update(b"DCS/experimental/state-certificate/N4/v1/no-freshness-SQL-acceptance");
    hash.update(profile_digest(Relation::PackedCanonicalIndex));
    hash.update(STATE_DOMAIN);
    hash.update(b"version-tag=SHA256(profile/full-canonical-images/C_key)/no-query-request");
    hash.update(b"same-packed-AEAD-canonical-index/independent-C_key/state87+587+6");
}
pub fn profile_digest(relation: Relation) -> [u8; 32] {
    let mut h = bfv_hiding_stark::profile_start(
        b"dcs/experiment/hiding-source-primitive-profile/v1",
        relation.kind_name().as_bytes(),
    );
    match relation {
        Relation::Bytes => profile(&mut h),
        Relation::CanonicalIndex => index_profile(&mut h),
        Relation::PackedCanonicalIndex => packed_index_profile(&mut h),
        Relation::FactorizedPackedCanonicalIndex => factorized::profile(&mut h),
        Relation::StateCertificate => certificate_profile(&mut h),
    }
    bfv_hiding_stark::profile_finish(h, relation.width(), 2)
}
