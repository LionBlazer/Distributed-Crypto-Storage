//! Reviewed PUBLIC NONSECRET SourceVersion fixture, shared in shape with the core test.
#![cfg(test)]

use crate::{
    Val,
    source::{self, circuit::Witness, statement::encode_digest, version::SourceVersionExpected},
};
use compact_store::{Commitment, Layout, Owner};
use p3_field::PrimeCharacteristicRing;
use zeroize::Zeroizing;

const PUBLIC_KEY: [u8; 32] = [0x51; 32];
const AGES: [u8; 4] = [255, 0, 255, 128];

pub(super) struct Fixture {
    pub expected: SourceVersionExpected,
    pub images: [Vec<u8>; 2],
    pub heads: [Commitment; 2],
}

impl Fixture {
    pub(super) fn checked(&self, key: [u8; 32], state: [u8; 32]) -> SourceVersionExpected {
        SourceVersionExpected::checked(
            [&self.images[0], &self.images[1]],
            [&self.heads[0], &self.heads[1]],
            key,
            state,
        )
        .unwrap()
    }

    pub(super) fn witness(&self) -> Witness {
        Witness::new(PUBLIC_KEY, [Val::ONE; 4], [Val::TWO; 4], AGES)
    }
}

pub(super) fn fixture() -> Fixture {
    // No live Owner/key/config or SDK object survives in this public fixture.
    let owner = Owner::from_key([0x42; 16], [0x73; 16], Zeroizing::new(PUBLIC_KEY));
    let data = [255, 0, 0, 0, 255, 255, 255, 0, 1, 128, 255, 0];
    let stored = owner
        .seal(
            Layout {
                schema: source::DATA_SCHEMA,
                row_width: 3,
                rows_per_page: 256,
                row_count: 4,
            },
            &data,
            source::statement::limits(),
        )
        .unwrap();
    // Reviewed core-owned PUBLIC index vector, shared with the original State fixture.
    let suffix: Vec<u8> =
        include_str!("../../../../compact-query/tests/fixtures/index-v3-four-row-suffix.hex")
            .lines()
            .filter(|line| !line.starts_with('#'))
            .flat_map(str::split_whitespace)
            .map(|hex| u8::from_str_radix(hex, 16).unwrap())
            .collect();
    assert_eq!(suffix.len(), 2224);
    let mut index = stored.commitment().encode().to_vec();
    index.extend_from_slice(&suffix);
    let indexed = owner
        .seal(
            Layout {
                schema: source::INDEX_SCHEMA,
                row_width: 1,
                rows_per_page: 4096,
                row_count: 2336,
            },
            &index,
            source::statement::limits(),
        )
        .unwrap();
    let images = [stored.encode(), indexed.encode()];
    let heads = [stored.commitment().clone(), indexed.commitment().clone()];
    let key = source::commitment::digest(&source::commitment::key_fields(
        &heads[0].encode(),
        PUBLIC_KEY,
        [Val::ONE; 4],
    ));
    let preliminary = SourceVersionExpected::checked(
        [&images[0], &images[1]],
        [&heads[0], &heads[1]],
        encode_digest(key),
        [0; 32],
    )
    .unwrap();
    let mut plain = [0; 2348];
    plain[..12].copy_from_slice(&data);
    plain[12..].copy_from_slice(&index);
    let state = source::commitment::digest(&source::commitment::opening_fields(
        preliminary.statement(),
        [Val::TWO; 4],
        &plain,
    ));
    let expected = SourceVersionExpected::checked(
        [&images[0], &images[1]],
        [&heads[0], &heads[1]],
        encode_digest(key),
        encode_digest(state),
    )
    .unwrap();
    assert_eq!(preliminary.version_id(), expected.version_id());
    Fixture {
        expected,
        images,
        heads,
    }
}
