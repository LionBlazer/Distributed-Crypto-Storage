// Public synthetic fixtures only. Fixed ordinals deliberately exercise actual page boundaries.
#[derive(Clone, Copy)]
struct NamedCase {
    name: &'static str,
    query: QuerySpec,
    count: usize,
}
const CASES: [NamedCase; 10] = [
    NamedCase {
        name: "eq0",
        query: QuerySpec::Equal(245),
        count: 0,
    },
    NamedCase {
        name: "eq1",
        query: QuerySpec::Equal(246),
        count: 1,
    },
    NamedCase {
        name: "eq4",
        query: QuerySpec::Equal(247),
        count: 4,
    },
    NamedCase {
        name: "eq16",
        query: QuerySpec::Equal(248),
        count: 16,
    },
    NamedCase {
        name: "eq256_two_posting_two_data",
        query: QuerySpec::Equal(230),
        count: 256,
    },
    NamedCase {
        name: "eq256_max",
        query: QuerySpec::Equal(255),
        count: 256,
    },
    NamedCase {
        name: "ge255_max",
        query: QuerySpec::AtLeast(255),
        count: 256,
    },
    NamedCase {
        name: "range256_two_posting_two_data",
        query: QuerySpec::ClosedRange {
            lower: 250,
            upper: 251,
        },
        count: 256,
    },
    NamedCase {
        name: "eq128_crossing_range_first_bucket",
        query: QuerySpec::Equal(250),
        count: 128,
    },
    NamedCase {
        name: "range21",
        query: QuerySpec::ClosedRange {
            lower: 246,
            upper: 248,
        },
        count: 21,
    },
];
fn public_rows(rows: usize, table: usize) -> Vec<PlainRow> {
    (0..rows)
        .map(|ordinal| {
            let (age, amount) = match ordinal {
                // Exactly1931 one-byte postings precede age230:2164+1931=4095.
                0..=1930 => (0, (ordinal % 257) as u16),
                1931..=2186 => (
                    230,
                    [0, 1, 255, 256, 65535, 257, 0, 255][(ordinal - 1931) % 8],
                ),
                // First absolute ordinal needs2 bytes, then3808 one-byte gaps:3810 bytes.
                2187..=5995 => (240, (ordinal % 65536) as u16),
                6025..=6152 => (250, ((ordinal * 137 + table * 641 + 29) % 65536) as u16),
                6153..=6280 => (251, ((ordinal * 137 + table * 641 + 29) % 65536) as u16),
                6281 => (246, 100 + (table % 1000) as u16),
                6282..=6285 => (247, 7), // Equal row values still have distinct ordinals.
                6286..=6301 => (248, 255 + (ordinal - 6286) as u16),
                6400..=6655 => (255, u16::MAX),
                // Valid count3 spans data pages3/4/5 and MUST reject before BFV.
                8191 | 8192 | 10240 => (249, 42),
                _ => (254, ((ordinal * 137 + table * 641 + 29) % 65536) as u16),
            };
            PlainRow { age, amount }
        })
        .collect()
}
#[cfg(test)]
mod fixture_tests {
    use super::*;
    #[test]
    fn named_complete_groups_include_two_real_256_groups_and_duplicate_values() {
        let rows = public_rows(12_000, 2);
        for case in CASES {
            let selected: Vec<_> = rows
                .iter()
                .enumerate()
                .filter(|(_, row)| case.query.contains(row.age))
                .map(|(ordinal, _)| ordinal as u64)
                .collect();
            assert_eq!(selected.len(), case.count, "{}", case.name);
            assert!(data_page_preflight(&selected).unwrap().len() <= PAGE_BUDGET);
        }
        let duplicate_rows: Vec<_> = rows.iter().filter(|row| row.age == 247).collect();
        assert_eq!(duplicate_rows.len(), 4);
        assert!(duplicate_rows.iter().all(|row| row.amount == 7));
        assert_eq!(
            data_page_preflight(&[8191, 8192, 10240]),
            Err(IndexError::PageBudget)
        );
    }
}
