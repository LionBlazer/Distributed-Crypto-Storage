//! Client-side SQL acquisition and shared proof-supported script preflight.
//!
//! Downloaded SQL is input data, never a script executed by the host. A prepared
//! import retains every validated literal row. The worker may initialize a new
//! encrypted database genesis from owner input, never replace an existing database
//! or use those rows to answer SQL. Reads and later writes keep Session proofs.
use compact_query::PlainRow;
use std::{fs::File, io::Read, time::Duration};
use storage_client::{SqlScript, SqlStatement};

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

/// Fully validated owner input for a new encrypted genesis. These rows may be
/// supplied to Session::create only for a new database. They are never a peer SQL
/// answer source or a replacement for proof-checked mutations of existing state.
#[derive(Debug)]
pub struct PreparedImport {
    pub sql: String,
    pub rows: Vec<PlainRow>,
    /// Counts lowered single-row INSERT operations as separate statements.
    pub statements: usize,
}

/// Validate the entire dump with the same parser used by the SQL console.
///
/// A dump creates exactly the currently supported table, followed by INSERTs.
/// Comments, IF NOT EXISTS, case differences and multi-row VALUES use the shared
/// script grammar. Unsupported trailing statements reject the entire input before
/// any mutation; no columns, constraints, records or tables are silently dropped.
/// This preflight has no storage handle. The caller must explicitly create a new
/// encrypted genesis after it succeeds; it must reject an existing database rather
/// than silently replacing it or applying a partially validated dump.
pub fn prepare_import(sql: &str) -> Result<PreparedImport, String> {
    if sql.len() > MAX_DUMP_BYTES {
        return Err("SQL dump exceeds the 8 MiB client input limit".into());
    }
    let script = SqlScript::parse(sql).map_err(|error| format!("Not imported: {error}"))?;
    let mut statements = script.statements().iter();
    if !matches!(statements.next(), Some(SqlStatement::CreateTable { .. })) {
        return Err("SQL import must begin with CREATE TABLE records; nothing was imported".into());
    }
    let mut rows = Vec::new();
    for statement in statements {
        let SqlStatement::Query {
            plan: sql_plan::QueryPlan::Insert { row },
            ..
        } = statement
        else {
            return Err("SQL import accepts one CREATE TABLE followed only by INSERT statements; nothing was imported".into());
        };
        rows.push(PlainRow {
            age: row.age,
            amount: row.amount,
        });
    }
    if rows.len() > MAX_IMPORT_ROWS {
        return Err(format!(
            "SQL dump exceeds the current encrypted import limit of {MAX_IMPORT_ROWS} rows; nothing was imported"
        ));
    }
    Ok(PreparedImport {
        sql: sql.into(),
        rows,
        statements: script.statement_count(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compatible_dump_preserves_every_literal_for_new_encrypted_genesis() {
        let sql = format!(
            "\u{feff}-- Owner-provided SQL\n{SUPPORTED_SCHEMA}\nINSERT INTO records (age, amount) VALUES (0, 0), (255, 65535); /* complete */ INSERT INTO records VALUES (18, 20);"
        );

        let prepared = prepare_import(&sql).expect("supported input");

        assert_eq!(prepared.sql, sql);
        assert_eq!(
            prepared.rows,
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
        assert_eq!(prepared.statements, 4);
    }

    #[test]
    fn console_and_dump_share_create_comments_and_insert_preflight() {
        let sql = "/* schema */ create table if not exists records (age tinyint unsigned not null, amount smallint unsigned not null); -- rows\ninsert into records values (18,20),(42,30);";

        let prepared = prepare_import(sql).expect("shared console grammar");

        assert_eq!(
            prepared.rows,
            vec![
                PlainRow {
                    age: 18,
                    amount: 20
                },
                PlainRow {
                    age: 42,
                    amount: 30
                }
            ]
        );
        assert_eq!(
            SqlScript::parse(&prepared.sql).unwrap().statement_count(),
            3
        );
    }

    #[test]
    fn unsupported_trailing_statement_rejects_the_entire_import() {
        let sql = format!(
            "{SUPPORTED_SCHEMA} INSERT INTO records VALUES (18,20); CREATE TABLE customers (name TEXT);"
        );

        assert!(prepare_import(&sql).is_err());
    }

    #[test]
    fn dump_preflight_does_not_turn_reads_or_updates_into_imported_rows() {
        for tail in [
            "SELECT * FROM records;",
            "UPDATE records SET amount = amount + 1;",
        ] {
            let sql = format!("{SUPPORTED_SCHEMA} {tail}");
            assert!(prepare_import(&sql).unwrap_err().contains("only by INSERT"));
        }
        assert!(
            prepare_import("INSERT INTO records VALUES (18,20);")
                .unwrap_err()
                .contains("begin with CREATE")
        );
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
            format!("{SUPPORTED_SCHEMA} /*! DROP TABLE records; */"),
            format!("{SUPPORTED_SCHEMA} /*M! DROP TABLE records; */"),
            format!("{SUPPORTED_SCHEMA} /* unterminated"),
            format!("{SUPPORTED_SCHEMA} /*/"),
        ] {
            assert!(prepare_import(&sql).is_err(), "accepted unsupported SQL: {sql}");
        }
    }

    #[test]
    fn row_and_input_bounds_fail_without_partial_output() {
        let rows = std::iter::repeat_n("(18,20)", MAX_IMPORT_ROWS + 1)
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!("{SUPPORTED_SCHEMA} INSERT INTO records VALUES {rows};");
        assert!(prepare_import(&sql).unwrap_err().contains("128 rows"));
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
                prepare_import(&dump.sql).is_err(),
                "full relational samples need missing engine/proof capabilities"
            );
        }
    }
}
