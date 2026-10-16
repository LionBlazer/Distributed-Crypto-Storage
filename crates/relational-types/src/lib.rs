//! Typed owner-side schema, SQL import and query planning contracts.
//!
//! This crate never executes a peer query or produces a verified query answer.
//! Imported plaintext belongs to the owner until its consumer encrypts it.

mod codec;
mod dump;
mod lexer;
mod select;

use serde::{Deserialize, Serialize};
use std::{cmp::Ordering, fmt};

pub use codec::{decode_row, decode_value, encode_row, encode_row_with_ranges, encode_value};
pub use dump::{ImportLimits, import_database_dump, validate_database};
pub use select::{
    CompareOp, Expr, OrderBy, RowWindow, SelectPlan, plan_select, plan_select_schemas,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataType {
    Integer {
        bits: u8,
        signed: bool,
    },
    Decimal {
        precision: u8,
        scale: u8,
    },
    Real {
        bits: u8,
    },
    Boolean,
    Text {
        max_chars: Option<usize>,
        unicode: bool,
        fixed: bool,
    },
    Binary {
        max_bytes: Option<usize>,
    },
    DateTime,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    pub seed: i64,
    pub increment: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Column {
    pub name: String,
    pub data_type: DataType,
    pub nullable: bool,
    pub default: Option<Value>,
    pub identity: Option<Identity>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForeignKey {
    pub columns: Vec<usize>,
    pub referenced_table: String,
    pub referenced_columns: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Index {
    pub name: String,
    pub columns: Vec<usize>,
    pub unique: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableSchema {
    pub name: String,
    pub columns: Vec<Column>,
    pub primary_key: Vec<usize>,
    pub foreign_keys: Vec<ForeignKey>,
    /// Source check expressions, preserved in the authenticated catalogue.
    pub checks: Vec<String>,
    pub indexes: Vec<Index>,
}

/// Validate schema shape even for an empty table or a deserialized public struct.
pub fn validate_schema(schema: &TableSchema) -> Result<(), Error> {
    use std::collections::HashSet;
    if schema.name.is_empty() || schema.columns.is_empty() || schema.columns.len() > 1024 {
        return Err(Error::new("invalid table name or column count"));
    }
    let mut names = HashSet::new();
    for column in &schema.columns {
        if column.name.is_empty() || !names.insert(column.name.to_ascii_lowercase()) {
            return Err(Error::new("empty or duplicate column name"));
        }
        validate_type(&column.data_type)?;
        if column.identity.as_ref().is_some_and(|identity| {
            identity.increment == 0 || !matches!(column.data_type, DataType::Integer { .. })
        }) {
            return Err(Error::new("invalid identity specification"));
        }
        if let Some(default) = &column.default {
            validate_value(column, default)?;
        }
    }
    for definition in std::iter::once(&schema.primary_key)
        .chain(schema.indexes.iter().map(|index| &index.columns))
        .chain(schema.foreign_keys.iter().map(|foreign| &foreign.columns))
    {
        let mut used = HashSet::new();
        for &column in definition {
            if column >= schema.columns.len() || !used.insert(column) {
                return Err(Error::new("invalid or repeated constraint column"));
            }
        }
    }
    if schema.indexes.iter().any(|index| index.columns.is_empty())
        || schema.foreign_keys.iter().any(|key| {
            key.columns.is_empty()
                || key.columns.len() != key.referenced_columns.len()
                || key.referenced_table.is_empty()
        })
    {
        return Err(Error::new("invalid index or foreign key shape"));
    }
    Ok(())
}

fn validate_type(data_type: &DataType) -> Result<(), Error> {
    let valid = match data_type {
        DataType::Integer { bits, .. } => [8, 16, 32, 64].contains(bits),
        DataType::Decimal { precision, scale } => {
            *precision > 0 && *precision <= 38 && scale <= precision
        }
        DataType::Real { bits } => [32, 64].contains(bits),
        DataType::Text {
            max_chars, fixed, ..
        } => {
            max_chars.is_none_or(|max| max > 0 && max <= 8 * 1024 * 1024)
                && (!*fixed || max_chars.is_some())
        }
        DataType::Binary { max_bytes } => {
            max_bytes.is_none_or(|max| max > 0 && max <= 8 * 1024 * 1024)
        }
        _ => true,
    };
    if valid {
        Ok(())
    } else {
        Err(Error::new("invalid or unsupported SQL type shape"))
    }
}

impl TableSchema {
    pub fn column_index(&self, name: &str) -> Result<usize, Error> {
        self.columns
            .iter()
            .position(|column| column.name.eq_ignore_ascii_case(name))
            .ok_or_else(|| Error::new(format!("unknown column {name:?} in table {:?}", self.name)))
    }
    pub fn validate_row(&self, row: &[Value]) -> Result<(), Error> {
        if row.len() != self.columns.len() {
            return Err(Error::new(format!(
                "table {:?} expects {} columns, received {}",
                self.name,
                self.columns.len(),
                row.len()
            )));
        }
        for (column, value) in self.columns.iter().zip(row) {
            validate_value(column, value)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Value {
    Null,
    Integer(i64),
    Decimal {
        unscaled: i128,
        scale: u8,
    },
    Real32(u32),
    Real64(u64),
    Boolean(bool),
    Text(String),
    Binary(Vec<u8>),
    /// Canonical Gregorian `YYYY-MM-DDTHH:MM:SS[.fraction]`, without a timezone.
    DateTime(String),
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => f.write_str("NULL"),
            Self::Integer(value) => write!(f, "{value}"),
            Self::Decimal { unscaled, scale } => {
                if *scale == 0 {
                    return write!(f, "{unscaled}");
                }
                let digits = unscaled.unsigned_abs().to_string();
                let padded = format!("{digits:0>width$}", width = usize::from(*scale) + 1);
                let cut = padded.len() - usize::from(*scale);
                write!(
                    f,
                    "{}{}.{}",
                    if *unscaled < 0 { "-" } else { "" },
                    &padded[..cut],
                    &padded[cut..]
                )
            }
            Self::Real32(bits) => write!(f, "{}", f32::from_bits(*bits)),
            Self::Real64(bits) => write!(f, "{}", f64::from_bits(*bits)),
            Self::Boolean(value) => f.write_str(if *value { "1" } else { "0" }),
            Self::Text(value) | Self::DateTime(value) => f.write_str(value),
            Self::Binary(bytes) => {
                f.write_str("0x")?;
                for byte in bytes {
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
        }
    }
}

pub type Row = Vec<Value>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportedTable {
    pub schema: TableSchema,
    pub rows: Vec<Row>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaObject {
    pub kind: String,
    pub name: String,
    pub definition: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportedDatabase {
    pub name: String,
    pub tables: Vec<ImportedTable>,
    /// Views and procedures are retained as source metadata; not executable plans.
    pub objects: Vec<SchemaObject>,
    /// Explicit interpretation of SQL Server installation/session directives.
    pub notices: Vec<String>,
}

impl ImportedDatabase {
    pub fn table(&self, name: &str) -> Result<&ImportedTable, Error> {
        self.tables
            .iter()
            .find(|table| table.schema.name.eq_ignore_ascii_case(name))
            .ok_or_else(|| Error::new(format!("unknown table {name:?}")))
    }
    pub fn row_count(&self) -> usize {
        self.tables.iter().map(|table| table.rows.len()).sum()
    }
    pub fn schemas(&self) -> Vec<TableSchema> {
        self.tables
            .iter()
            .map(|table| table.schema.clone())
            .collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    pub message: String,
}
impl Error {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for Error {}

/// Ordering used to construct an owner-private complete index, never a peer SQL executor.
/// NULL is deliberately unordered: SQL predicates need three-valued NULL semantics.
pub fn compare_values(left: &Value, right: &Value) -> Result<Ordering, Error> {
    let mismatch = || Error::new("values have incompatible types or NULL has no comparison order");
    match (left, right) {
        (Value::Integer(a), Value::Integer(b)) => Ok(a.cmp(b)),
        (
            Value::Decimal {
                unscaled: a,
                scale: sa,
            },
            Value::Decimal {
                unscaled: b,
                scale: sb,
            },
        ) => {
            let scale = (*sa).max(*sb);
            let a = a
                .checked_mul(
                    10_i128
                        .checked_pow(u32::from(scale - *sa))
                        .ok_or_else(mismatch)?,
                )
                .ok_or_else(mismatch)?;
            let b = b
                .checked_mul(
                    10_i128
                        .checked_pow(u32::from(scale - *sb))
                        .ok_or_else(mismatch)?,
                )
                .ok_or_else(mismatch)?;
            Ok(a.cmp(&b))
        }
        (Value::Real32(a), Value::Real32(b)) => f32::from_bits(*a)
            .partial_cmp(&f32::from_bits(*b))
            .ok_or_else(mismatch),
        (Value::Real64(a), Value::Real64(b)) => f64::from_bits(*a)
            .partial_cmp(&f64::from_bits(*b))
            .ok_or_else(mismatch),
        (Value::Boolean(a), Value::Boolean(b)) => Ok(a.cmp(b)),
        (Value::Text(a), Value::Text(b)) => Ok(a.cmp(b)),
        (Value::Binary(a), Value::Binary(b)) => Ok(a.cmp(b)),
        (Value::DateTime(a), Value::DateTime(b)) => Ok(a.cmp(b)),
        _ => Err(mismatch()),
    }
}

/// Compare validated values using the column's text-padding semantics.
/// Variable text preserves spaces; only fixed CHAR/NCHAR ignores trailing U+0020.
/// Text order is ordinal, with no implicit locale or server-default collation.
pub fn compare_typed_values(
    data_type: &DataType,
    left: &Value,
    right: &Value,
) -> Result<Ordering, Error> {
    match (data_type, left, right) {
        (DataType::Text { fixed: true, .. }, Value::Text(a), Value::Text(b)) => {
            Ok(a.trim_end_matches(' ').cmp(b.trim_end_matches(' ')))
        }
        _ => compare_values(left, right),
    }
}

pub(crate) fn validate_value(column: &Column, value: &Value) -> Result<(), Error> {
    validate_type(&column.data_type)?;
    if matches!(value, Value::Null) {
        return if column.nullable {
            Ok(())
        } else {
            Err(Error::new(format!(
                "column {:?} does not allow NULL",
                column.name
            )))
        };
    }
    let valid = match (&column.data_type, value) {
        (DataType::Integer { bits, signed }, Value::Integer(n)) => {
            if ![8, 16, 32, 64].contains(bits) {
                false
            } else if *signed {
                if *bits == 64 {
                    true
                } else {
                    *n >= -(1_i64 << (*bits - 1)) && *n < (1_i64 << (*bits - 1))
                }
            } else {
                *n >= 0 && (*bits == 64 || (*n as u64) < (1_u64 << *bits))
            }
        }
        (DataType::Decimal { precision, scale }, Value::Decimal { unscaled, scale: s }) => {
            *precision > 0
                && *precision <= 38
                && scale <= precision
                && s == scale
                && unscaled.unsigned_abs() < 10_u128.pow(u32::from(*precision))
        }
        (DataType::Real { bits: 32 }, Value::Real32(bits)) => f32::from_bits(*bits).is_finite(),
        (DataType::Real { bits: 64 }, Value::Real64(bits)) => f64::from_bits(*bits).is_finite(),
        (DataType::Boolean, Value::Boolean(_)) => true,
        (
            DataType::Text {
                max_chars, unicode, ..
            },
            Value::Text(text),
        ) => max_chars.is_none_or(|max| {
            if *unicode {
                text.encode_utf16().count() <= max
            } else {
                text.chars().count() <= max
            }
        }),
        (DataType::Binary { max_bytes }, Value::Binary(bytes)) => {
            max_bytes.is_none_or(|max| bytes.len() <= max)
        }
        (DataType::DateTime, Value::DateTime(value)) => {
            canonical_datetime(value).is_ok_and(|canonical| canonical == *value)
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(Error::new(format!(
            "invalid value for column {:?} ({:?})",
            column.name, column.data_type
        )))
    }
}

pub(crate) fn literal_for_type(
    data_type: &DataType,
    literal: &lexer::TokenKind,
) -> Result<Value, Error> {
    use lexer::TokenKind;
    validate_type(data_type)?;
    if literal.word_is("NULL") {
        return Ok(Value::Null);
    }
    let number = match literal {
        TokenKind::Number(s) => Some(s.as_str()),
        _ => None,
    };
    let text = match literal {
        TokenKind::String(s) => Some(s.as_str()),
        _ => None,
    };
    let value = match data_type {
        DataType::Integer { .. } => Value::Integer(
            number
                .ok_or_else(|| Error::new("expected an integer literal"))?
                .parse()
                .map_err(|_| Error::new("invalid integer"))?,
        ),
        DataType::Decimal { scale, .. } => Value::Decimal {
            unscaled: decimal_unscaled(
                number.ok_or_else(|| Error::new("expected decimal literal"))?,
                *scale,
            )?,
            scale: *scale,
        },
        DataType::Real { bits: 32 } => Value::Real32(
            number
                .ok_or_else(|| Error::new("expected real literal"))?
                .parse::<f32>()
                .map_err(|_| Error::new("invalid real"))?
                .to_bits(),
        ),
        DataType::Real { bits: 64 } => Value::Real64(
            number
                .ok_or_else(|| Error::new("expected float literal"))?
                .parse::<f64>()
                .map_err(|_| Error::new("invalid float"))?
                .to_bits(),
        ),
        DataType::Boolean => Value::Boolean(match number {
            Some("0") => false,
            Some("1") => true,
            _ => return Err(Error::new("BIT requires 0 or 1")),
        }),
        DataType::Text {
            max_chars,
            fixed,
            unicode,
        } => {
            let mut text = text
                .ok_or_else(|| Error::new("expected text literal"))?
                .to_owned();
            if *fixed && let Some(length) = max_chars {
                let used = if *unicode {
                    text.encode_utf16().count()
                } else {
                    text.chars().count()
                };
                if used > *length {
                    return Err(Error::new("fixed text literal is too long"));
                }
                text.extend(std::iter::repeat_n(' ', length - used));
            }
            Value::Text(text)
        }
        DataType::Binary { .. } => Value::Binary(match literal {
            TokenKind::Binary(bytes) => bytes.clone(),
            _ => return Err(Error::new("expected hexadecimal binary literal")),
        }),
        DataType::DateTime => Value::DateTime(canonical_datetime(
            text.ok_or_else(|| Error::new("expected datetime string"))?,
        )?),
        _ => return Err(Error::new("unsupported numeric width")),
    };
    Ok(value)
}

fn decimal_unscaled(text: &str, scale: u8) -> Result<i128, Error> {
    let negative = text.starts_with('-');
    let unsigned = text.trim_start_matches(['-', '+']);
    let mut parts = unsigned.split('.');
    let whole = parts.next().unwrap_or("0");
    let fraction = parts.next().unwrap_or("");
    if parts.next().is_some()
        || !whole.chars().all(|c| c.is_ascii_digit())
        || !fraction.chars().all(|c| c.is_ascii_digit())
    {
        return Err(Error::new("invalid exact decimal"));
    }
    let retained = fraction.get(..usize::from(scale)).unwrap_or(fraction);
    if fraction
        .get(usize::from(scale)..)
        .is_some_and(|s| s.bytes().any(|c| c != b'0'))
    {
        return Err(Error::new("decimal precision would be lost"));
    }
    let digits = format!("{whole}{retained:0<width$}", width = usize::from(scale));
    let value = digits
        .parse::<i128>()
        .map_err(|_| Error::new("decimal is out of range"))?;
    Ok(if negative { -value } else { value })
}

pub(crate) fn canonical_datetime(text: &str) -> Result<String, Error> {
    let (date, time) = text.split_once(['T', ' ']).unwrap_or((text, "00:00:00"));
    let date_parts = date
        .split(['-', '/'])
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Error::new("invalid datetime date"))?;
    if date_parts.len() != 3 {
        return Err(Error::new("expected a complete datetime date"));
    }
    let (year, month, day) = if date.contains('/') {
        (date_parts[2], date_parts[0], date_parts[1])
    } else {
        (date_parts[0], date_parts[1], date_parts[2])
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
        _ => 0,
    };
    if !(1..=9999).contains(&year) || day == 0 || day > days {
        return Err(Error::new("datetime date out of range"));
    }
    let (clock, fraction) = time.split_once('.').unwrap_or((time, ""));
    let parts = clock
        .split(':')
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Error::new("invalid datetime time"))?;
    if parts.len() != 3
        || parts[0] > 23
        || parts[1] > 59
        || parts[2] > 59
        || fraction.len() > 7
        || !fraction.bytes().all(|c| c.is_ascii_digit())
    {
        return Err(Error::new("datetime time out of range"));
    }
    let fraction = fraction.trim_end_matches('0');
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}{}{}",
        parts[0],
        parts[1],
        parts[2],
        if fraction.is_empty() { "" } else { "." },
        fraction
    ))
}
