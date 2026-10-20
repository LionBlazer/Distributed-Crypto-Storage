//! One bounded lexer for query and transaction syntax. Quoted identifiers never
//! participate in keyword/operator matching. PG18 UTF8 identifier bytes are
//! accepted only as tokens; each parser production still decides its own grammar.
use super::unsupported;
use crate::Error;

pub(super) enum Token {
    Word(String),
    QuotedIdentifier(String),
    Number(String),
    Symbol(String),
}

impl Token {
    pub(super) fn syntax(&self) -> Option<&str> {
        match self {
            Self::Word(value) | Self::Number(value) | Self::Symbol(value) => Some(value),
            Self::QuotedIdentifier(_) => None,
        }
    }
}

pub(super) fn tokenize(sql: &str) -> Result<Vec<Token>, Error> {
    let bytes = sql.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii_whitespace() {
            index += 1;
        } else if identifier_start(byte) {
            let start = index;
            index += 1;
            while index < bytes.len() && identifier_continue(bytes[index]) {
                index += 1;
            }
            tokens.push(Token::Word(sql[start..index].to_ascii_uppercase()));
        } else if byte.is_ascii_digit() {
            let start = index;
            while index < bytes.len() && bytes[index].is_ascii_digit() {
                index += 1;
            }
            // Do not turn the former rejected token 1WHERE into 1, WHERE.
            // PostgreSQL also rejects trailing identifier junk after a number.
            if bytes
                .get(index)
                .is_some_and(|byte| identifier_start(*byte) || *byte == b'$')
            {
                return Err(unsupported("identifier directly after numeric literal"));
            }
            tokens.push(Token::Number(sql[start..index].into()));
        } else if byte == b'"' {
            let (value, next) = quoted_identifier(sql, index + 1)?;
            tokens.push(Token::QuotedIdentifier(value));
            index = next;
        } else if matches!(byte, b'<' | b'>' | b'!') {
            let length = if bytes.get(index + 1) == Some(&b'=')
                || (byte == b'<' && bytes.get(index + 1) == Some(&b'>'))
            {
                2
            } else {
                1
            };
            tokens.push(Token::Symbol(sql[index..index + length].into()));
            index += length;
        } else if b"(),*+=;-".contains(&byte) {
            tokens.push(Token::Symbol((byte as char).to_string()));
            index += 1;
        } else {
            return Err(unsupported("unsupported character or operator"));
        }
    }
    Ok(tokens)
}

// scan.l ident_start/ident_cont use all high-bit bytes. A Rust str already
// guarantees valid UTF8, and stopping at an ASCII delimiter preserves its boundary.
fn identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_' || byte >= 0x80
}

fn identifier_continue(byte: u8) -> bool {
    identifier_start(byte) || byte.is_ascii_digit() || byte == b'$'
}

fn quoted_identifier(sql: &str, mut index: usize) -> Result<(String, usize), Error> {
    let bytes = sql.as_bytes();
    let mut value = String::new();
    let mut start = index;
    while index < bytes.len() {
        match bytes[index] {
            0 => return Err(unsupported("NUL in quoted identifier")),
            b'"' => {
                value.push_str(&sql[start..index]);
                index += 1;
                if bytes.get(index) == Some(&b'"') {
                    value.push('"');
                    index += 1;
                    start = index;
                } else if value.is_empty() {
                    return Err(unsupported("empty quoted identifier"));
                } else {
                    return Ok((value, index));
                }
            }
            _ => index += 1,
        }
    }
    Err(unsupported("unterminated quoted identifier"))
}

// PG18 ColId = IDENT | unreserved_keyword | col_name_keyword. These are exactly
// the RESERVED_KEYWORD and TYPE_FUNC_NAME_KEYWORD exclusions from REL_18_0
// src/include/parser/kwlist.h; bare-label status does not decide ColId.
// Classify the full token BEFORE identifier truncation.
pub(super) fn col_id(word: &str) -> bool {
    !matches!(
        word,
        "ALL"
            | "ANALYSE"
            | "ANALYZE"
            | "AND"
            | "ANY"
            | "ARRAY"
            | "AS"
            | "ASC"
            | "ASYMMETRIC"
            | "AUTHORIZATION"
            | "BINARY"
            | "BOTH"
            | "CASE"
            | "CAST"
            | "CHECK"
            | "COLLATE"
            | "COLLATION"
            | "COLUMN"
            | "CONCURRENTLY"
            | "CONSTRAINT"
            | "CREATE"
            | "CROSS"
            | "CURRENT_CATALOG"
            | "CURRENT_DATE"
            | "CURRENT_ROLE"
            | "CURRENT_SCHEMA"
            | "CURRENT_TIME"
            | "CURRENT_TIMESTAMP"
            | "CURRENT_USER"
            | "DEFAULT"
            | "DEFERRABLE"
            | "DESC"
            | "DISTINCT"
            | "DO"
            | "ELSE"
            | "END"
            | "EXCEPT"
            | "FALSE"
            | "FETCH"
            | "FOR"
            | "FOREIGN"
            | "FREEZE"
            | "FROM"
            | "FULL"
            | "GRANT"
            | "GROUP"
            | "HAVING"
            | "ILIKE"
            | "IN"
            | "INITIALLY"
            | "INNER"
            | "INTERSECT"
            | "INTO"
            | "IS"
            | "ISNULL"
            | "JOIN"
            | "LATERAL"
            | "LEADING"
            | "LEFT"
            | "LIKE"
            | "LIMIT"
            | "LOCALTIME"
            | "LOCALTIMESTAMP"
            | "NATURAL"
            | "NOT"
            | "NOTNULL"
            | "NULL"
            | "OFFSET"
            | "ON"
            | "ONLY"
            | "OR"
            | "ORDER"
            | "OUTER"
            | "OVERLAPS"
            | "PLACING"
            | "PRIMARY"
            | "REFERENCES"
            | "RETURNING"
            | "RIGHT"
            | "SELECT"
            | "SESSION_USER"
            | "SIMILAR"
            | "SOME"
            | "SYMMETRIC"
            | "SYSTEM_USER"
            | "TABLE"
            | "TABLESAMPLE"
            | "THEN"
            | "TO"
            | "TRAILING"
            | "TRUE"
            | "UNION"
            | "UNIQUE"
            | "USER"
            | "USING"
            | "VARIADIC"
            | "VERBOSE"
            | "WHEN"
            | "WHERE"
            | "WINDOW"
            | "WITH"
    )
}
