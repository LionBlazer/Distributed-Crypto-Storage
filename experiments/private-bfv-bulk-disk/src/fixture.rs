//! Explicitly PUBLIC sparse fixture; never read by peer query execution.
use compact_query::PlainRow;
pub(crate) const ROWS: usize = 1_000_000;
pub(crate) const PAGE_ROWS: u32 = 2048;
#[derive(Clone, Copy, Debug)]
pub(crate) struct Case {
    pub name: &'static str,
    pub age: u8,
}
pub(crate) const CASES: [Case; 3] = [
    Case {
        name: "absent",
        age: 254,
    },
    Case {
        name: "point",
        age: 250,
    },
    Case {
        name: "sparse256",
        age: 255,
    },
];
pub(crate) fn public_rows() -> Vec<PlainRow> {
    let mut rows = (0..ROWS)
        .map(|i| PlainRow {
            age: (i % 200) as u8,
            amount: ((i * 13 + 7) % 65536) as u16,
        })
        .collect::<Vec<_>>();
    for i in 0..256 {
        rows[i * (ROWS - 1) / 255] = PlainRow {
            age: 255,
            amount: u16::MAX,
        };
    }
    rows[ROWS / 2] = PlainRow {
        age: 250,
        amount: 4095,
    };
    rows
}
/// Invoke only AFTER the timed query. These values never feed owner preparation.
pub(crate) fn oracle(case: Case) -> (Vec<u64>, u32) {
    let rows = public_rows();
    let ids = rows
        .iter()
        .enumerate()
        .filter(|(_, row)| row.age == case.age)
        .map(|(i, _)| i as u64)
        .collect::<Vec<_>>();
    let sum = ids
        .iter()
        .map(|i| u32::from(rows[*i as usize].amount))
        .sum();
    (ids, sum)
}
