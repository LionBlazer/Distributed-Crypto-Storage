use crate::{Error, Row, TableSchema, Value};
use std::ops::Range;

const ROW_MAGIC: &[u8; 8] = b"DCSROW01";
const MAX_FIELD_BYTES: usize = 8 * 1024 * 1024;
const MAX_ROW_BYTES: usize = 16 * 1024 * 1024;

/// Canonical self-describing field encoding. No key or peer state is involved.
pub fn encode_value(value: &Value) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    match value {
        Value::Null => bytes.push(0),
        Value::Integer(value) => {
            bytes.push(1);
            bytes.extend(value.to_le_bytes());
        }
        Value::Decimal { unscaled, scale } => {
            bytes.extend([2, *scale]);
            bytes.extend(unscaled.to_le_bytes());
        }
        Value::Real32(bits) => {
            bytes.push(3);
            bytes.extend(bits.to_le_bytes());
        }
        Value::Real64(bits) => {
            bytes.push(4);
            bytes.extend(bits.to_le_bytes());
        }
        Value::Boolean(value) => bytes.extend([5, u8::from(*value)]),
        Value::Text(value) => variable(&mut bytes, 6, value.as_bytes())?,
        Value::Binary(value) => variable(&mut bytes, 7, value)?,
        Value::DateTime(value) => variable(&mut bytes, 8, value.as_bytes())?,
    }
    Ok(bytes)
}

fn variable(bytes: &mut Vec<u8>, tag: u8, value: &[u8]) -> Result<(), Error> {
    if value.len() > MAX_FIELD_BYTES {
        return Err(Error::new("field exceeds the canonical codec byte budget"));
    }
    let length =
        u32::try_from(value.len()).map_err(|_| Error::new("field exceeds encoding length"))?;
    bytes.push(tag);
    bytes.extend(length.to_le_bytes());
    bytes.extend(value);
    Ok(())
}

pub fn decode_value(bytes: &[u8]) -> Result<Value, Error> {
    if bytes.len() > MAX_FIELD_BYTES + 5 {
        return Err(Error::new("field exceeds the canonical codec byte budget"));
    }
    let invalid = || Error::new("invalid canonical field encoding");
    let (&tag, body) = bytes.split_first().ok_or_else(invalid)?;
    match tag {
        0 if body.is_empty() => Ok(Value::Null),
        1 if body.len() == 8 => Ok(Value::Integer(i64::from_le_bytes(
            body.try_into().map_err(|_| invalid())?,
        ))),
        2 if body.len() == 17 => Ok(Value::Decimal {
            scale: body[0],
            unscaled: i128::from_le_bytes(body[1..].try_into().map_err(|_| invalid())?),
        }),
        3 if body.len() == 4 => Ok(Value::Real32(u32::from_le_bytes(
            body.try_into().map_err(|_| invalid())?,
        ))),
        4 if body.len() == 8 => Ok(Value::Real64(u64::from_le_bytes(
            body.try_into().map_err(|_| invalid())?,
        ))),
        5 if body == [0] => Ok(Value::Boolean(false)),
        5 if body == [1] => Ok(Value::Boolean(true)),
        6..=8 if body.len() >= 4 => {
            let length = u32::from_le_bytes(body[..4].try_into().map_err(|_| invalid())?) as usize;
            if length != body.len() - 4 {
                return Err(invalid());
            }
            if tag == 7 {
                return Ok(Value::Binary(body[4..].to_vec()));
            }
            let text = std::str::from_utf8(&body[4..])
                .map_err(|_| invalid())?
                .to_owned();
            Ok(if tag == 6 {
                Value::Text(text)
            } else {
                Value::DateTime(text)
            })
        }
        _ => Err(invalid()),
    }
}

pub fn encode_row(schema: &TableSchema, row: &Row) -> Result<Vec<u8>, Error> {
    encode_row_with_ranges(schema, row).map(|(bytes, _)| bytes)
}

/// Field ranges address the original encoded bytes, for homomorphic projection masks.
pub fn encode_row_with_ranges(
    schema: &TableSchema,
    row: &Row,
) -> Result<(Vec<u8>, Vec<Range<usize>>), Error> {
    crate::validate_schema(schema)?;
    schema.validate_row(row)?;
    let mut bytes = ROW_MAGIC.to_vec();
    bytes.extend(
        u32::try_from(row.len())
            .map_err(|_| Error::new("too many fields"))?
            .to_le_bytes(),
    );
    let mut ranges = Vec::with_capacity(row.len());
    for value in row {
        let field = encode_value(value)?;
        if bytes
            .len()
            .checked_add(field.len() + 4)
            .is_none_or(|length| length > MAX_ROW_BYTES)
        {
            return Err(Error::new("row exceeds the canonical codec byte budget"));
        }
        bytes.extend(
            u32::try_from(field.len())
                .map_err(|_| Error::new("field too long"))?
                .to_le_bytes(),
        );
        let start = bytes.len();
        bytes.extend(field);
        ranges.push(start..bytes.len());
    }
    Ok((bytes, ranges))
}

pub fn decode_row(schema: &TableSchema, bytes: &[u8]) -> Result<Row, Error> {
    crate::validate_schema(schema)?;
    if bytes.len() > MAX_ROW_BYTES {
        return Err(Error::new("row exceeds the canonical codec byte budget"));
    }
    let invalid = || Error::new("invalid canonical row encoding");
    if bytes.len() < 12 || &bytes[..8] != ROW_MAGIC {
        return Err(invalid());
    }
    let count = u32::from_le_bytes(bytes[8..12].try_into().map_err(|_| invalid())?) as usize;
    if count != schema.columns.len() {
        return Err(invalid());
    }
    let mut offset = 12_usize;
    let mut row = Vec::with_capacity(count);
    for _ in 0..count {
        let header_end = offset.checked_add(4).ok_or_else(invalid)?;
        let length = u32::from_le_bytes(
            bytes
                .get(offset..header_end)
                .ok_or_else(invalid)?
                .try_into()
                .map_err(|_| invalid())?,
        ) as usize;
        let end = header_end.checked_add(length).ok_or_else(invalid)?;
        row.push(decode_value(
            bytes.get(header_end..end).ok_or_else(invalid)?,
        )?);
        offset = end;
    }
    if offset != bytes.len() {
        return Err(invalid());
    }
    schema.validate_row(&row)?;
    Ok(row)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_lengths_and_trailing_fields_cannot_be_decoded_as_a_row() {
        let database = crate::import_database_dump(
            "CREATE TABLE Items(id int NOT NULL); INSERT INTO Items VALUES(7);",
            Default::default(),
        )
        .unwrap();
        let table = &database.tables[0];
        let valid = encode_row(&table.schema, &table.rows[0]).unwrap();
        let mut forged = valid.clone();
        forged[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode_row(&table.schema, &forged).is_err());
        let mut forged = valid.clone();
        forged.extend([0]);
        assert!(decode_row(&table.schema, &forged).is_err());
        assert!(decode_value(&[6, 255, 255, 255, 255]).is_err());
        assert!(decode_value(&[5, 2]).is_err());
        assert!(decode_value(&vec![0; MAX_FIELD_BYTES + 6]).is_err());
        assert_eq!(
            decode_row(&table.schema, &valid).unwrap(),
            vec![Value::Integer(7)]
        );
    }
}
