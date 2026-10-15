//! Bounded owner-entered CSV and public row fixtures for the playground.
use crate::{LabError, MAX_LAB_ROWS, PlainRow};

/// Public synthetic data only. Each GUI run generates fresh secret keys in memory.
pub fn sample_rows(count: usize) -> Result<Vec<PlainRow>, LabError> {
    if count > MAX_LAB_ROWS {
        return Err(LabError::InvalidInput(
            "Use at most 128 sample rows.".into(),
        ));
    }
    let pattern = [
        PlainRow {
            age: 17,
            amount: 10,
        },
        PlainRow {
            age: 18,
            amount: 20,
        },
        PlainRow {
            age: 42,
            amount: 30,
        },
        PlainRow { age: 7, amount: 40 },
    ];
    Ok((0..count)
        .map(|index| pattern[index % pattern.len()])
        .collect())
}

pub fn format_rows(rows: &[PlainRow]) -> String {
    rows.iter()
        .map(|row| format!("{},{}", row.age, row.amount))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Parses owner-entered age,amount lines before key generation or database replacement.
pub fn parse_rows(text: &str) -> Result<Vec<PlainRow>, LabError> {
    if text.len() > 16_384 {
        return Err(LabError::InvalidInput(
            "Fixture exceeds 16384 bytes.".into(),
        ));
    }
    let mut rows = Vec::new();
    for (line, value) in text.lines().enumerate() {
        if value.trim().is_empty() {
            continue;
        }
        if rows.len() == MAX_LAB_ROWS {
            return Err(LabError::InvalidInput("Use at most 128 rows.".into()));
        }
        let error = || {
            LabError::InvalidInput(format!(
                "Line {}: expected age 0..255,amount 0..65535.",
                line + 1
            ))
        };
        let (age, amount) = value.split_once(',').ok_or_else(error)?;
        rows.push(PlainRow {
            age: age.trim().parse().map_err(|_| error())?,
            amount: amount.trim().parse().map_err(|_| error())?,
        });
    }
    Ok(rows)
}
