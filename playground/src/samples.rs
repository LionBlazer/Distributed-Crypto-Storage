//! Client-side SQL acquisition and shared proof-supported script preflight.
//!
//! Downloaded SQL is input data, never a script executed by the host. A prepared
//! import retains every validated literal row. The worker may initialize a new
//! encrypted database genesis from owner input, never replace an existing database
//! or use those rows to answer SQL. Accepted queries remain proof-checked;
//! unsupported typed transitions are rejected by the storage client.
use relational_types::{ImportLimits, ImportedDatabase, import_database_dump};
use std::{fs::File, io::Read, time::Duration};

pub const MAX_DUMP_BYTES: usize = 8 * 1024 * 1024;
#[cfg(test)]
pub const SUPPORTED_SCHEMA: &str =
    "CREATE TABLE records (age TINYINT UNSIGNED NOT NULL, amount SMALLINT UNSIGNED NOT NULL);";
const SCHEMA_NOTE: &str = "Typed tables are encrypted on import. SELECT uses authenticated indexes and proved FHE projection. Unsupported SQL is rejected; imported views and procedures are metadata, not executable queries.";

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

/// Fully validated typed owner input for a new encrypted genesis. No table or row
/// is truncated to fit the historical age/amount experiment.
#[derive(Debug)]
pub struct PreparedImport {
    pub sql: String,
    pub database: ImportedDatabase,
    /// Informational count of imported tables and rows; not executed SQL operations.
    pub statements: usize,
}

/// Parse the complete source with the typed importer before starting network work.
/// SQL installation directives are interpreted as import format metadata; external
/// host programs are never invoked. Unsupported schema/values fail as a whole.
pub fn prepare_import(sql: &str) -> Result<PreparedImport, String> {
    if sql.len() > MAX_DUMP_BYTES {
        return Err("SQL dump exceeds the 8 MiB client input limit".into());
    }
    let database = import_database_dump(sql, ImportLimits::default())
        .map_err(|error| format!("Not imported: {error}"))?;
    let statements = database.tables.len() + database.row_count();
    Ok(PreparedImport {
        sql: sql.into(),
        database,
        statements,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use relational_types::Value;

    #[test]
    fn typed_import_preserves_multiple_tables_null_text_and_exact_money() {
        let sql = "CREATE TABLE Customers (CustomerID NCHAR(5) NOT NULL PRIMARY KEY, CompanyName NVARCHAR(80) NULL); INSERT INTO Customers VALUES (N'ALFKI',N'Alfreds'),(N'EMPTY',NULL); CREATE TABLE Products (ProductID INT NOT NULL, UnitPrice MONEY NULL); INSERT INTO Products VALUES (1,18.5);";

        let prepared = prepare_import(sql).expect("typed public fixture");

        assert_eq!(prepared.sql, sql);
        assert_eq!(prepared.database.tables.len(), 2);
        assert_eq!(prepared.database.row_count(), 3);
        assert_eq!(
            prepared.database.table("Customers").unwrap().rows[1][1],
            Value::Null
        );
        assert_eq!(
            prepared.database.table("Products").unwrap().rows[0][1],
            Value::Decimal {
                unscaled: 185000,
                scale: 4
            }
        );
    }

    #[test]
    fn import_keeps_every_row_beyond_the_historical_128_limit() {
        let rows = (0..400)
            .map(|n| format!("({n},'Customer {n}')"))
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "CREATE TABLE Customers (ID INT NOT NULL, Name NVARCHAR(80) NOT NULL); INSERT INTO Customers VALUES {rows};"
        );

        let prepared = prepare_import(&sql).unwrap();

        assert_eq!(prepared.database.row_count(), 400);
        assert_eq!(
            prepared.database.tables[0].rows[399][0],
            Value::Integer(399)
        );
    }

    #[test]
    fn malformed_values_and_unsupported_trailing_execution_fail_without_partial_import() {
        for sql in [
            "CREATE TABLE Customers (ID INT NOT NULL); INSERT INTO Customers VALUES ('not an integer');",
            "CREATE TABLE Customers (ID INT NOT NULL); EXEC xp_cmdshell 'command';",
            "CREATE TABLE Customers (ID INT NOT NULL); INSERT INTO Customers VALUES (1); SELECT * FROM Customers;",
            "CREATE TABLE Customers (ID INT NOT NULL); /* unterminated",
        ] {
            assert!(
                prepare_import(sql).is_err(),
                "accepted unsupported import: {sql}"
            );
        }
    }

    #[test]
    fn input_bounds_and_binary_backups_fail_before_parsing_or_network_work() {
        assert!(read_bounded(std::io::repeat(b' ').take(MAX_DUMP_BYTES as u64 + 1)).is_err());
        assert!(decode_dump("local".into(), vec![0xff, 0xfe]).is_err());
        assert!(decode_dump("local".into(), b"SELECT\0".to_vec()).is_err());
    }

    #[test]
    #[ignore = "downloads the official Northwind script over HTTPS; no dataset is retained"]
    fn official_northwind_download_has_all_tables_and_more_than_128_rows() {
        let dump = download_sample("northwind").expect("download official upstream SQL");

        let prepared = prepare_import(&dump.sql).expect("complete typed Northwind import");

        assert_eq!(prepared.database.tables.len(), 13);
        assert_eq!(prepared.database.table("Customers").unwrap().rows.len(), 91);
        assert_eq!(prepared.database.table("Orders").unwrap().rows.len(), 830);
        assert_eq!(
            prepared.database.table("Order Details").unwrap().rows.len(),
            2155
        );
    }
}
