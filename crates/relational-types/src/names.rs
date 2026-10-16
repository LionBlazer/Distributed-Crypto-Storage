//! Explicit identifier binding: canonical PostgreSQL catalog vs source dump names.
use crate::{
    Error, TableSchema,
    lexer::{Parser, TokenKind},
    pg_keywords::{self, Category},
};

pub(crate) const MAX_IDENTIFIER_BYTES: usize = 63;
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rules {
    PostgreSql,
    SqlServerDump,
}
#[derive(Clone, Copy)]
pub(crate) struct Scope<'a> {
    pub schema: &'a TableSchema,
    pub alias: Option<&'a str>,
    pub rules: Rules,
}
impl Rules {
    pub fn ident(self, parser: &mut Parser<'_>, dotted: bool) -> Result<String, Error> {
        let token = parser.take()?;
        let value = match (self, token) {
            (Self::PostgreSql, TokenKind::Word(word)) => {
                let bytes = word.as_bytes();
                if !bytes
                    .first()
                    .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_' || *b >= 128)
                    || !bytes
                        .iter()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'$') || *b >= 128)
                {
                    return Err(Error::new("invalid PostgreSQL unquoted identifier"));
                }
                let word = word.to_ascii_lowercase();
                if !dotted
                    && matches!(
                        pg_keywords::category(&word),
                        Some(Category::Reserved | Category::TypeFunction)
                    )
                {
                    return Err(Error::new(format!(
                        "keyword {word:?} requires identifier quotes"
                    )));
                }
                word
            }
            (Self::PostgreSql, TokenKind::Quoted(word)) => word,
            (
                Self::SqlServerDump,
                TokenKind::Word(word) | TokenKind::Quoted(word) | TokenKind::Bracketed(word),
            ) => word,
            _ => {
                return Err(Error::new(
                    "expected an identifier in the selected language",
                ));
            }
        };
        if value.is_empty() || value.contains('\0') {
            return Err(Error::new("empty or NUL identifier"));
        }
        if self == Self::SqlServerDump {
            return Ok(value);
        }
        // PG18 UTF-8 folds ASCII only, then clips decoded bytes at a character boundary.
        let mut end = value.len().min(MAX_IDENTIFIER_BYTES);
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        Ok(value[..end].to_owned())
    }
    fn same(self, left: &str, right: &str) -> bool {
        match self {
            Self::PostgreSql => left == right,
            Self::SqlServerDump => left.eq_ignore_ascii_case(right),
        }
    }
}
impl Scope<'_> {
    pub fn column(self, parser: &mut Parser<'_>) -> Result<usize, Error> {
        let mut parts = vec![self.rules.ident(parser, false)?];
        while parser.eat_symbol('.') {
            if parts.len() == 3 {
                return Err(Error::new(
                    "column qualification exceeds schema/table/column",
                ));
            }
            parts.push(self.rules.ident(parser, true)?);
        }
        let name = parts.pop().expect("nonempty identifier");
        let visible = self.alias.unwrap_or(&self.schema.name);
        let valid = match parts.as_slice() {
            [] => true,
            [table] => self.rules.same(table, visible),
            [namespace, table] if self.alias.is_none() => {
                self.rules.same(
                    namespace,
                    match self.rules {
                        Rules::PostgreSql => "public",
                        Rules::SqlServerDump => "dbo",
                    },
                ) && self.rules.same(table, visible)
            }
            _ => false,
        };
        if !valid {
            return Err(Error::new(format!(
                "unknown column qualifier {parts:?}; expected {visible:?}"
            )));
        }
        match self.rules {
            Rules::PostgreSql => self.schema.column_index(&name),
            Rules::SqlServerDump => source_column(self.schema, &name),
        }
    }
}
pub(crate) fn source_column(schema: &TableSchema, name: &str) -> Result<usize, Error> {
    let mut found = schema
        .columns
        .iter()
        .enumerate()
        .filter(|(_, c)| c.name.eq_ignore_ascii_case(name));
    let first = found
        .next()
        .ok_or_else(|| Error::new(format!("unknown source column {name:?}")))?
        .0;
    if found.next().is_some() {
        return Err(Error::new(format!(
            "ambiguous SQL Server source column {name:?}"
        )));
    }
    Ok(first)
}
pub(crate) fn relation(parser: &mut Parser<'_>) -> Result<String, Error> {
    let first = Rules::PostgreSql.ident(parser, false)?;
    if !parser.eat_symbol('.') {
        return Ok(first);
    }
    let table = Rules::PostgreSql.ident(parser, true)?;
    if first != "public" {
        return Err(Error::new(format!(
            "unsupported PostgreSQL schema {first:?}; this catalog uses public"
        )));
    }
    if parser.eat_symbol('.') {
        return Err(Error::new("cross-database qualification is unsupported"));
    }
    Ok(table)
}
/// Live catalog admission never truncates/renames losslessly imported metadata.
/// Only public's base tables are addressable; other source objects remain metadata.
pub fn validate_postgresql_catalog(schemas: &[TableSchema]) -> Result<(), Error> {
    let mut names = std::collections::HashSet::new();
    for schema in schemas {
        crate::validate_schema(schema)?;
        if !names.insert(&schema.name) {
            return Err(Error::new("duplicate exact table name"));
        }
        for name in
            std::iter::once(&schema.name).chain(schema.columns.iter().map(|column| &column.name))
        {
            if name.len() > MAX_IDENTIFIER_BYTES {
                return Err(Error::new(format!(
                    "catalog identifier {name:?} exceeds PostgreSQL's 63-byte live limit; source metadata was not renamed"
                )));
            }
        }
    }
    Ok(())
}
