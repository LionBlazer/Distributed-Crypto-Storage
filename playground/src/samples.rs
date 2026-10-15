//! Client-side SQL dump acquisition and complete validation before encrypted upload.
//!
//! Downloaded SQL is data to inspect, never a script executed by the host. Import
//! accepts only the exact schema the encrypted engine can currently preserve.
use compact_query::PlainRow;
use std::{fs::File, io::Read, time::Duration};

pub const MAX_DUMP_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_IMPORT_ROWS: usize = 128;
pub const SUPPORTED_SCHEMA: &str =
    "CREATE TABLE records (age TINYINT UNSIGNED NOT NULL, amount SMALLINT UNSIGNED NOT NULL);";
const SCHEMA_NOTE: &str = "Full import requires multiple tables, text/decimal/date types and SQL constraints, which the encrypted engine does not yet support. Download and inspect only; nothing is silently converted.";

#[derive(Clone, Copy, Debug)]
pub struct SampleDatabase {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub source_url: &'static str,
    pub download_url: &'static str,
    pub approximate_size: &'static str,
    pub support_note: &'static str,
}

/// Public upstream SQL scripts. No dataset bytes are included in this binary.
pub const CATALOG: &[SampleDatabase] = &[
    SampleDatabase {
        id: "northwind",
        name: "Northwind · Microsoft",
        description: "Orders, products, customers and employees. SQL Server SQL script.",
        source_url: "https://github.com/microsoft/sql-server-samples/tree/master/samples/databases/northwind-pubs",
        download_url: "https://raw.githubusercontent.com/microsoft/sql-server-samples/master/samples/databases/northwind-pubs/instnwnd.sql",
        approximate_size: "1.0 MiB SQL",
        support_note: SCHEMA_NOTE,
    },
    SampleDatabase {
        id: "pubs",
        name: "pubs · Microsoft",
        description: "Books, authors and sales. A smaller SQL Server SQL script.",
        source_url: "https://github.com/microsoft/sql-server-samples/tree/master/samples/databases/northwind-pubs",
        download_url: "https://raw.githubusercontent.com/microsoft/sql-server-samples/master/samples/databases/northwind-pubs/instpubs.sql",
        approximate_size: "123 KiB SQL",
        support_note: SCHEMA_NOTE,
    },
    SampleDatabase {
        id: "chinook",
        name: "Chinook",
        description: "Music store, tracks and invoices. SQLite SQL script, release 1.4.5.",
        source_url: "https://github.com/lerocha/chinook-database/releases/tag/v1.4.5",
        download_url: "https://github.com/lerocha/chinook-database/releases/download/v1.4.5/Chinook_Sqlite.sql",
        approximate_size: "597 KiB SQL",
        support_note: SCHEMA_NOTE,
    },
];

pub const ADVENTUREWORKS_SOURCE: &str =
    "https://learn.microsoft.com/en-us/sql/samples/adventureworks-install-configure";

#[derive(Debug)]
pub struct DownloadedDump {
    pub sample_id: String,
    pub sql: String,
    pub bytes: usize,
}

/// Runs on a client background thread. TLS, redirects, response size and total
/// request duration are bounded. The response is neither executed nor persisted.
pub fn download_sample(id: &str) -> Result<DownloadedDump, String> {
    let sample = CATALOG
        .iter()
        .find(|sample| sample.id == id)
        .ok_or_else(|| "Unknown sample database".to_string())?;
    let client = reqwest::blocking::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::limited(5))
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(60))
        .user_agent("DistributedCryptoStorage/sample-import")
        .build()
        .map_err(|error| format!("Cannot prepare sample download: {error}"))?;
    let response = client
        .get(sample.download_url)
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .map_err(|error| format!("Cannot download {}: {error}", sample.name))?;
    if response
        .content_length()
        .is_some_and(|size| size > MAX_DUMP_BYTES as u64)
    {
        return Err("SQL dump exceeds the 8 MiB client download limit".into());
    }
    decode_dump(sample.id.into(), read_bounded(response)?)
}

/// The supplied local file is read with the same byte bound as downloads. No
/// external program or database is invoked to interpret the dump.
pub fn load_local_dump(path: &str) -> Result<DownloadedDump, String> {
    let file = File::open(path).map_err(|error| format!("Cannot open SQL dump: {error}"))?;
    if !file
        .metadata()
        .map_err(|error| error.to_string())?
        .is_file()
    {
        return Err("Select a regular SQL dump file".into());
    }
    decode_dump("local".into(), read_bounded(file)?)
}

fn read_bounded(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_DUMP_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("Cannot read SQL dump: {error}"))?;
    if bytes.len() > MAX_DUMP_BYTES {
        return Err("SQL dump exceeds the 8 MiB client input limit".into());
    }
    Ok(bytes)
}

fn decode_dump(sample_id: String, bytes: Vec<u8>) -> Result<DownloadedDump, String> {
    let length = bytes.len();
    let sql = String::from_utf8(bytes).map_err(|_| {
        "SQL dump must use UTF-8 text, not a binary .bak/.sqlite backup".to_string()
    })?;
    if sql.contains('\0') {
        return Err("SQL dump contains NUL bytes; use UTF-8 SQL text, not a binary backup".into());
    }
    Ok(DownloadedDump {
        sample_id,
        sql,
        bytes: length,
    })
}

/// Validates the entire script and returns owner-supplied input rows only when
/// every statement is supported. The caller may then explicitly create a new
/// encrypted database through the normal Session path. Errors return no partial
/// rows, and this parser has no storage/network handle with which to mutate data.
///
/// Grammar: one exact CREATE TABLE declaration, followed by zero or more INSERTs
/// into records, each with an optional `(age, amount)` list and one or more value
/// tuples. Statements require semicolons. SQL comments are allowed. Other DDL,
/// constraints, transactions, expressions and types are rejected, never skipped.
pub fn parse_dump(sql: &str) -> Result<Vec<PlainRow>, String> {
    if sql.len() > MAX_DUMP_BYTES {
        return Err("SQL dump exceeds the 8 MiB client input limit".into());
    }
    let mut parser = DumpParser {
        source: sql.trim_start_matches('\u{feff}'),
        offset: 0,
    };
    for token in [
        "CREATE", "TABLE", "records", "(", "age", "TINYINT", "UNSIGNED", "NOT", "NULL", ",",
        "amount", "SMALLINT", "UNSIGNED", "NOT", "NULL", ")", ";",
    ] {
        parser.expect(token)?;
    }
    let mut rows = Vec::new();
    while parser.peek()?.is_some() {
        for token in ["INSERT", "INTO", "records"] {
            parser.expect(token)?;
        }
        if parser.take("(")? {
            for token in ["age", ",", "amount", ")"] {
                parser.expect(token)?;
            }
        }
        parser.expect("VALUES")?;
        loop {
            parser.expect("(")?;
            let age = parser.number::<u8>("age must be an unsigned integer in 0..=255")?;
            parser.expect(",")?;
            let amount = parser.number::<u16>("amount must be an unsigned integer in 0..=65535")?;
            parser.expect(")")?;
            if rows.len() == MAX_IMPORT_ROWS {
                return Err(format!(
                    "SQL dump exceeds the current encrypted import limit of {MAX_IMPORT_ROWS} rows; no rows were imported"
                ));
            }
            rows.push(PlainRow { age, amount });
            if !parser.take(",")? {
                break;
            }
        }
        parser.expect(";")?;
    }
    Ok(rows)
}

struct DumpParser<'a> {
    source: &'a str,
    offset: usize,
}
impl<'a> DumpParser<'a> {
    fn next(&mut self) -> Result<Option<&'a str>, String> {
        let bytes = self.source.as_bytes();
        loop {
            while bytes.get(self.offset).is_some_and(u8::is_ascii_whitespace) {
                self.offset += 1;
            }
            let rest = &self.source[self.offset..];
            if rest.starts_with("--") {
                self.offset += rest.find('\n').unwrap_or(rest.len());
            } else if let Some(comment) = rest.strip_prefix("/*") {
                let end = comment
                    .find("*/")
                    .ok_or_else(|| self.error("unterminated comment"))?;
                if comment[..end].contains("/*")
                    || comment.starts_with('!')
                    || comment.starts_with("M!")
                    || comment.starts_with("m!")
                {
                    return Err(self.error("nested or executable comments are unsupported"));
                }
                self.offset += end + 4;
            } else {
                break;
            }
        }
        let start = self.offset;
        match bytes.get(start) {
            None => return Ok(None),
            Some(byte) if byte.is_ascii_alphanumeric() || *byte == b'_' => {
                while bytes
                    .get(self.offset)
                    .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                {
                    self.offset += 1;
                }
            }
            Some(byte) if b"(),;".contains(byte) => self.offset += 1,
            _ => {
                return Err(self.error(
                    "quoted identifiers, strings, expressions or unsupported SQL punctuation",
                ));
            }
        }
        Ok(Some(&self.source[start..self.offset]))
    }
    fn peek(&mut self) -> Result<Option<&'a str>, String> {
        let offset = self.offset;
        let result = self.next();
        self.offset = offset;
        result
    }
    fn take(&mut self, expected: &str) -> Result<bool, String> {
        if self
            .peek()?
            .is_some_and(|token| token.eq_ignore_ascii_case(expected))
        {
            self.next()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    fn expect(&mut self, expected: &str) -> Result<(), String> {
        if self.take(expected)? {
            Ok(())
        } else {
            Err(self.error(&format!("expected {expected}")))
        }
    }
    fn number<T: std::str::FromStr>(&mut self, message: &str) -> Result<T, String> {
        let token = self.next()?.ok_or_else(|| self.error(message))?;
        if token.is_empty() || !token.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(self.error(message));
        }
        token.parse().map_err(|_| self.error(message))
    }
    fn error(&self, message: &str) -> String {
        format!(
            "Unsupported SQL dump near byte {}: {message}. Current encrypted schema: records(age: u8, amount: u16), at most {MAX_IMPORT_ROWS} rows. Nothing was imported; arbitrary tables, text, constraints and SQL Server batches require encrypted engine/proof support.",
            self.offset
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_supported_dump_preserves_values_and_column_order() {
        let sql = format!(
            "\u{feff}-- Owner-provided SQL\n{SUPPORTED_SCHEMA}\nINSERT INTO records (age, amount) VALUES (0, 0), (255, 65535); /* complete */ INSERT INTO records VALUES (18, 20);"
        );
        let rows = parse_dump(&sql).expect("supported owner input");
        assert_eq!(
            rows,
            vec![
                PlainRow { age: 0, amount: 0 },
                PlainRow {
                    age: 255,
                    amount: 65535
                },
                PlainRow {
                    age: 18,
                    amount: 20
                }
            ]
        );
    }

    #[test]
    fn unsupported_trailing_statement_rejects_the_entire_import() {
        let sql = format!(
            "{SUPPORTED_SCHEMA} INSERT INTO records VALUES (18,20); CREATE TABLE customers (name TEXT);"
        );
        let error = parse_dump(&sql).expect_err("must not return valid prefix rows");
        assert!(error.contains("Nothing was imported"));
    }

    #[test]
    fn incompatible_schema_and_values_are_not_reinterpreted_or_truncated() {
        for sql in [
            "CREATE TABLE customers (age TINYINT UNSIGNED NOT NULL, amount SMALLINT UNSIGNED NOT NULL);".into(),
            "CREATE TABLE records (age TINYINT, amount SMALLINT);".into(),
            format!("{SUPPORTED_SCHEMA} INSERT INTO records VALUES (256,1);"),
            format!("{SUPPORTED_SCHEMA} INSERT INTO records VALUES (1,65536);"),
            format!("{SUPPORTED_SCHEMA} INSERT INTO records VALUES (-1,2);"),
            format!("{SUPPORTED_SCHEMA} INSERT INTO records VALUES (1,'2');"),
            format!("{SUPPORTED_SCHEMA} INSERT INTO records (amount, age) VALUES (1,2);"),
            format!("{SUPPORTED_SCHEMA} INSERT INTO records VALUES (1,2)"),
            format!("{SUPPORTED_SCHEMA} /*! DROP TABLE records; */"),
            format!("{SUPPORTED_SCHEMA} /*M! DROP TABLE records; */"),
            format!("{SUPPORTED_SCHEMA} /* unterminated"),
            format!("{SUPPORTED_SCHEMA} /*/"),
        ] {
            assert!(parse_dump(&sql).is_err(), "accepted unsupported SQL: {sql}");
        }
    }

    #[test]
    fn row_and_input_bounds_fail_without_partial_output() {
        let rows = std::iter::repeat_n("(18,20)", MAX_IMPORT_ROWS + 1)
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!("{SUPPORTED_SCHEMA} INSERT INTO records VALUES {rows};");
        assert!(parse_dump(&sql).unwrap_err().contains("128 rows"));
        assert!(read_bounded(std::io::repeat(b' ').take(MAX_DUMP_BYTES as u64 + 1)).is_err());
        assert!(decode_dump("local".into(), vec![0xff, 0xfe]).is_err());
        assert!(decode_dump("local".into(), b"SELECT\0".to_vec()).is_err());
    }

    #[test]
    #[ignore = "downloads current public upstream SQL over HTTPS; no dataset is retained"]
    fn public_catalog_downloads_are_sql_text_and_cannot_fake_a_supported_import() {
        for sample in CATALOG {
            let dump = download_sample(sample.id).expect("download official upstream SQL");
            assert_eq!(dump.sample_id, sample.id);
            assert!(dump.bytes > 100_000 && dump.bytes <= MAX_DUMP_BYTES);
            assert!(dump.sql.to_ascii_uppercase().contains("CREATE TABLE"));
            assert!(
                parse_dump(&dump.sql).is_err(),
                "full relational samples need missing engine/proof capabilities"
            );
        }
    }
}
