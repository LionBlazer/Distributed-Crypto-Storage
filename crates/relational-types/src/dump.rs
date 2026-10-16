use crate::{
    Column, DataType, Error, ForeignKey, Identity, ImportedDatabase, ImportedTable, Index, Row,
    SchemaObject, TableSchema, Value, encode_value,
    lexer::{Parser, Token, TokenKind, lex, split_commas, token_text},
    literal_for_type,
};
use std::collections::{HashMap, HashSet};

#[derive(Clone, Copy, Debug)]
pub struct ImportLimits {
    pub max_sql_bytes: usize,
    pub max_tables: usize,
    pub max_columns_per_table: usize,
    pub max_rows: usize,
    pub max_cell_bytes: usize,
    pub max_decoded_bytes: usize,
}
impl Default for ImportLimits {
    fn default() -> Self {
        Self {
            max_sql_bytes: 16 * 1024 * 1024,
            max_tables: 1024,
            max_columns_per_table: 1024,
            max_rows: 1_000_000,
            max_cell_bytes: 8 * 1024 * 1024,
            max_decoded_bytes: 128 * 1024 * 1024,
        }
    }
}

/// Parse an owner-supplied SQL Server table dump without executing its program text.
///
/// All base tables/columns/rows are retained. Installation cleanup, session options,
/// disabled checks and stored programs receive explicit catalogue notices. Declared
/// primary/foreign/unique/check constraints are validated over the complete import.
pub fn import_database_dump(sql: &str, limits: ImportLimits) -> Result<ImportedDatabase, Error> {
    if sql.len() > limits.max_sql_bytes {
        return Err(Error::new("SQL dump exceeds configured byte limit"));
    }
    let tokens = lex(sql)?;
    let mut database=ImportedDatabase{name:"database".into(),tables:Vec::new(),objects:Vec::new(),notices:vec!["Text comparison uses case-sensitive Unicode ordinal ordering; variable text preserves trailing spaces and fixed CHAR/NCHAR ignores trailing U+0020. No server-default collation is assumed.".into()]};
    let mut row_count = 0;
    let mut decoded_bytes = 0;
    let mut start = 0;
    for i in 0..=tokens.len() {
        let is_go = i < tokens.len()
            && tokens[i].kind.word_is("GO")
            && (i == 0 || tokens[i - 1].line != tokens[i].line)
            && (i + 1 == tokens.len() || tokens[i + 1].line != tokens[i].line);
        if i == tokens.len() || is_go {
            parse_batch(
                sql,
                &tokens[start..i],
                &mut database,
                limits,
                &mut row_count,
                &mut decoded_bytes,
            )?;
            start = i + 1;
        }
    }
    if database.tables.is_empty() {
        return Err(Error::new("SQL dump contains no base tables"));
    }
    validate_database(&database)?;
    Ok(database)
}

fn parse_batch(
    sql: &str,
    tokens: &[Token],
    database: &mut ImportedDatabase,
    limits: ImportLimits,
    row_count: &mut usize,
    decoded_bytes: &mut usize,
) -> Result<(), Error> {
    if tokens.is_empty() {
        return Ok(());
    }
    let mut parser = Parser::new(tokens);
    // A dump is an import format, never an administrative script executor.
    if parser.eat_word("IF") {
        parser.expect_word("EXISTS")?;
        let probe = parser.group()?;
        if !probe
            .first()
            .is_some_and(|token| token.kind.word_is("SELECT"))
        {
            return Err(Error::new(
                "installation cleanup must use an EXISTS SELECT probe",
            ));
        }
        parser.expect_word("DROP")?;
        let kind = parser.ident()?;
        if !["TABLE", "VIEW", "PROCEDURE"]
            .iter()
            .any(|allowed| kind.eq_ignore_ascii_case(allowed))
        {
            return Err(Error::new("unsupported installation cleanup object"));
        }
        parser.object_name()?;
        parser.eat_symbol(';');
        if !parser.done() {
            return Err(Error::new(
                "installation cleanup cannot contain additional statements",
            ));
        }
        database.notices.push(format!(
            "Installation cleanup retained without execution: {}",
            token_text(tokens)
        ));
        return Ok(());
    }
    if parser.eat_word("CREATE") {
        let kind = parser.ident()?;
        if kind.eq_ignore_ascii_case("VIEW")
            || kind.eq_ignore_ascii_case("PROCEDURE")
            || kind.eq_ignore_ascii_case("PROC")
        {
            let name = parser.object_name()?;
            let definition = sql[tokens[0].start..tokens[tokens.len() - 1].end].to_owned();
            database.objects.push(SchemaObject {
                kind: kind.to_ascii_lowercase(),
                name,
                definition,
            });
            database.notices.push("Stored program retained as catalogue source; its SQL is not executed by the table importer.".into());
            return Ok(());
        }
    }
    parser.position = 0;
    while !parser.done() {
        if parser.eat_symbol(';') {
            continue;
        }
        if parser.eat_word("CREATE") {
            let unique = parser.eat_word("UNIQUE");
            if parser.eat_word("TABLE") {
                if unique {
                    return Err(Error::new("unexpected UNIQUE TABLE"));
                }
                create_table(&mut parser, database, limits)?;
            } else if parser.eat_word("INDEX") {
                create_index(&mut parser, database, unique)?;
            } else if parser.eat_word("DATABASE") {
                if !database.tables.is_empty() {
                    return Err(Error::new("CREATE DATABASE must precede table data"));
                }
                database.name = parser.ident()?;
            } else {
                return Err(Error::new("unsupported CREATE object in dump"));
            }
        } else if parser.eat_word("INSERT") {
            insert_rows(&mut parser, database, limits, row_count, decoded_bytes)?;
        } else if parser.eat_word("ALTER") {
            parser.expect_word("TABLE")?;
            let name = parser.object_name()?;
            let table = table_mut(database, &name)?;
            if parser.eat_word("ADD") {
                parse_constraint(&mut parser, &mut table.schema)?;
                storage_placement(&mut parser)?;
            } else {
                let disabled = parser.eat_word("NOCHECK");
                if !disabled {
                    parser.expect_word("CHECK")?;
                }
                parser.expect_word("CONSTRAINT")?;
                parser.expect_word("ALL")?;
                database.notices.push(format!("ALTER TABLE {name} {} CONSTRAINT ALL is an import ordering directive; final imported constraints are validated.",if disabled{"NOCHECK"}else{"CHECK"}));
            }
        } else if parser.eat_word("SET") {
            parse_set(&mut parser, database)?;
        } else if parser.eat_word("USE") {
            database.name = parser.ident()?;
        } else {
            return Err(Error::new(format!(
                "unsupported dump statement near {:?}",
                parser.peek()
            )));
        }
    }
    Ok(())
}

fn parse_set(parser: &mut Parser<'_>, database: &mut ImportedDatabase) -> Result<(), Error> {
    let option = parser.ident()?;
    if option.eq_ignore_ascii_case("IDENTITY_INSERT") {
        let name = parser.object_name()?;
        let state = parser.ident()?;
        if !state.eq_ignore_ascii_case("ON") && !state.eq_ignore_ascii_case("OFF") {
            return Err(Error::new("IDENTITY_INSERT expects ON or OFF"));
        }
        database.notices.push(format!(
            "IDENTITY_INSERT {name} {state}: dump supplies explicit identity values."
        ));
    } else if option.eq_ignore_ascii_case("NOCOUNT")
        || option.eq_ignore_ascii_case("QUOTED_IDENTIFIER")
    {
        let state = parser.ident()?;
        if !state.eq_ignore_ascii_case("ON") {
            return Err(Error::new(format!("unsupported SET {option} {state}")));
        }
        database.notices.push(format!(
            "SET {option} ON recognized as SQL Server session formatting."
        ));
    } else if option.eq_ignore_ascii_case("DATEFORMAT") {
        let format = parser.ident()?;
        if !format.eq_ignore_ascii_case("mdy") {
            return Err(Error::new("this import format accepts DATEFORMAT mdy"));
        }
        database
            .notices
            .push("SET DATEFORMAT mdy applied to datetime literals.".into());
    } else {
        return Err(Error::new(format!("unsupported session option {option:?}")));
    }
    Ok(())
}

fn table_mut<'a>(
    database: &'a mut ImportedDatabase,
    name: &str,
) -> Result<&'a mut ImportedTable, Error> {
    database
        .tables
        .iter_mut()
        .find(|table| table.schema.name.eq_ignore_ascii_case(name))
        .ok_or_else(|| Error::new(format!("unknown table {name:?}")))
}
fn create_table(
    parser: &mut Parser<'_>,
    database: &mut ImportedDatabase,
    limits: ImportLimits,
) -> Result<(), Error> {
    let if_not_exists = if parser.eat_word("IF") {
        parser.expect_word("NOT")?;
        parser.expect_word("EXISTS")?;
        true
    } else {
        false
    };
    let name = parser.object_name()?;
    if database
        .tables
        .iter()
        .any(|table| table.schema.name.eq_ignore_ascii_case(&name))
    {
        if if_not_exists {
            return Err(Error::new(
                "duplicate table declaration in an import is ambiguous",
            ));
        }
        return Err(Error::new(format!("duplicate table {name:?}")));
    }
    if database.tables.len() >= limits.max_tables {
        return Err(Error::new("import exceeds configured table limit"));
    }
    let body = parser.group()?;
    let fragments = split_commas(body);
    let mut schema = TableSchema {
        name,
        columns: Vec::new(),
        primary_key: Vec::new(),
        foreign_keys: Vec::new(),
        checks: Vec::new(),
        indexes: Vec::new(),
    };
    // Columns precede table constraints in the accepted format, as in Northwind.
    let mut constraints = Vec::new();
    for fragment in fragments {
        let mut field = Parser::new(fragment);
        if field.peek().is_some_and(|token| {
            ["CONSTRAINT", "PRIMARY", "FOREIGN", "CHECK", "UNIQUE"]
                .iter()
                .any(|word| token.word_is(word))
        }) {
            constraints.push(fragment);
            continue;
        }
        if schema.columns.len() >= limits.max_columns_per_table {
            return Err(Error::new("import exceeds configured column limit"));
        }
        let column_name = field.ident()?;
        if schema
            .columns
            .iter()
            .any(|column| column.name.eq_ignore_ascii_case(&column_name))
        {
            return Err(Error::new(format!("duplicate column {column_name:?}")));
        }
        let data_type = parse_type(&mut field)?;
        if matches!(data_type,DataType::Text{max_chars:Some(width),fixed:true,..} if width>limits.max_cell_bytes)
        {
            return Err(Error::new(
                "fixed text width exceeds configured cell byte limit",
            ));
        }
        let mut column = Column {
            name: column_name,
            data_type,
            nullable: true,
            default: None,
            identity: None,
        };
        let mut inline_primary = false;
        while !field.done() {
            if field.eat_word("NOT") {
                field.expect_word("NULL")?;
                column.nullable = false;
            } else if field.eat_word("NULL") {
                column.nullable = true;
            } else if field.eat_word("IDENTITY") {
                let identity = field.group()?;
                let mut p = Parser::new(identity);
                let seed = p
                    .number()?
                    .parse()
                    .map_err(|_| Error::new("invalid identity seed"))?;
                p.expect_symbol(',')?;
                let increment = p
                    .number()?
                    .parse()
                    .map_err(|_| Error::new("invalid identity increment"))?;
                if !p.done() || increment == 0 {
                    return Err(Error::new("invalid identity specification"));
                }
                column.identity = Some(Identity { seed, increment });
            } else if field.eat_word("CONSTRAINT") {
                field.ident()?;
            } else if field.eat_word("DEFAULT") {
                let literal = if field.peek() == Some(&TokenKind::Symbol('(')) {
                    let group = field.group()?;
                    let mut p = Parser::new(group);
                    let literal = p.literal()?;
                    if !p.done() {
                        return Err(Error::new("only literal defaults are supported"));
                    }
                    literal
                } else {
                    field.literal()?
                };
                column.default = Some(literal_for_type(&column.data_type, &literal)?);
            } else if field.eat_word("PRIMARY") {
                field.expect_word("KEY")?;
                inline_primary = true;
                column.nullable = false;
            } else {
                return Err(Error::new(format!(
                    "unsupported column modifier {:?}",
                    field.peek()
                )));
            }
        }
        if inline_primary {
            schema.primary_key.push(schema.columns.len());
        }
        schema.columns.push(column);
    }
    if schema.columns.is_empty() {
        return Err(Error::new("table must contain columns"));
    }
    for fragment in constraints {
        let mut constraint = Parser::new(fragment);
        parse_constraint(&mut constraint, &mut schema)?;
        if !constraint.done() {
            return Err(Error::new(format!(
                "unsupported trailing table constraint syntax {:?}",
                constraint.peek()
            )));
        }
    }
    storage_placement(parser)?;
    database.tables.push(ImportedTable {
        schema,
        rows: Vec::new(),
    });
    Ok(())
}

fn parse_type(parser: &mut Parser<'_>) -> Result<DataType, Error> {
    let name = parser.ident()?.to_ascii_lowercase();
    let args = if parser.peek() == Some(&TokenKind::Symbol('(')) {
        Some(parser.group()?)
    } else {
        None
    };
    let length = || -> Result<Option<usize>, Error> {
        match args {
            None => Ok(None),
            Some(tokens) => {
                let mut p = Parser::new(tokens);
                if p.eat_word("MAX") {
                    if !p.done() {
                        return Err(Error::new("invalid MAX width"));
                    }
                    return Ok(None);
                }
                let size = p
                    .number()?
                    .parse::<usize>()
                    .map_err(|_| Error::new("invalid type width"))?;
                if size == 0 || !p.done() {
                    return Err(Error::new("invalid type width"));
                }
                Ok(Some(size))
            }
        }
    };
    let signed = !parser.eat_word("UNSIGNED");
    Ok(match name.as_str() {
        "tinyint" => DataType::Integer {
            bits: 8,
            signed: false,
        },
        "smallint" => DataType::Integer { bits: 16, signed },
        "int" | "integer" => DataType::Integer { bits: 32, signed },
        "bigint" => DataType::Integer { bits: 64, signed },
        "money" => DataType::Decimal {
            precision: 19,
            scale: 4,
        },
        "smallmoney" => DataType::Decimal {
            precision: 10,
            scale: 4,
        },
        "decimal" | "numeric" => {
            let mut p = Parser::new(
                args.ok_or_else(|| Error::new("decimal requires precision and scale"))?,
            );
            let precision = p
                .number()?
                .parse::<u8>()
                .map_err(|_| Error::new("invalid decimal precision"))?;
            let scale = if p.eat_symbol(',') {
                p.number()?
                    .parse::<u8>()
                    .map_err(|_| Error::new("invalid decimal scale"))?
            } else {
                0
            };
            if !p.done() || precision == 0 || precision > 38 || scale > precision {
                return Err(Error::new("invalid decimal precision/scale"));
            }
            DataType::Decimal { precision, scale }
        }
        "real" => DataType::Real { bits: 32 },
        "float" => DataType::Real { bits: 64 },
        "bit" | "boolean" => DataType::Boolean,
        "char" | "nchar" | "varchar" | "nvarchar" => DataType::Text {
            max_chars: length()?,
            unicode: name.starts_with('n'),
            fixed: name == "char" || name == "nchar",
        },
        "text" | "ntext" => DataType::Text {
            max_chars: None,
            unicode: name == "ntext",
            fixed: false,
        },
        "image" | "binary" | "varbinary" => DataType::Binary {
            max_bytes: length()?,
        },
        "datetime" | "datetime2" | "smalldatetime" | "date" => DataType::DateTime,
        _ => return Err(Error::new(format!("unsupported SQL type {name:?}"))),
    })
}

fn names(parser: &mut Parser<'_>) -> Result<Vec<String>, Error> {
    let group = parser.group()?;
    let mut p = Parser::new(group);
    let mut values = Vec::new();
    loop {
        values.push(p.ident()?);
        p.eat_word("ASC");
        p.eat_word("DESC");
        if !p.eat_symbol(',') {
            break;
        }
    }
    if !p.done() {
        return Err(Error::new("invalid column list"));
    }
    Ok(values)
}
fn columns(schema: &TableSchema, names: Vec<String>) -> Result<Vec<usize>, Error> {
    names.iter().map(|name| schema.column_index(name)).collect()
}
fn parse_constraint(parser: &mut Parser<'_>, schema: &mut TableSchema) -> Result<(), Error> {
    let name = if parser.eat_word("CONSTRAINT") {
        Some(parser.ident()?)
    } else {
        None
    };
    if parser.eat_word("PRIMARY") {
        parser.expect_word("KEY")?;
        parser.eat_word("CLUSTERED");
        parser.eat_word("NONCLUSTERED");
        if !schema.primary_key.is_empty() {
            return Err(Error::new("duplicate primary key"));
        }
        schema.primary_key = columns(schema, names(parser)?)?;
        for &column in &schema.primary_key {
            schema.columns[column].nullable = false;
        }
    } else if parser.eat_word("FOREIGN") {
        parser.expect_word("KEY")?;
        let source = columns(schema, names(parser)?)?;
        parser.expect_word("REFERENCES")?;
        let referenced_table = parser.object_name()?;
        let referenced_columns = names(parser)?;
        if source.len() != referenced_columns.len() {
            return Err(Error::new("foreign key width mismatch"));
        }
        schema.foreign_keys.push(ForeignKey {
            columns: source,
            referenced_table,
            referenced_columns,
        });
    } else if parser.eat_word("CHECK") {
        let expression = parser.group()?;
        schema.checks.push(token_text(expression));
    } else if parser.eat_word("UNIQUE") {
        parser.eat_word("CLUSTERED");
        parser.eat_word("NONCLUSTERED");
        let index_columns = columns(schema, names(parser)?)?;
        schema.indexes.push(Index {
            name: name.unwrap_or_else(|| format!("unique_{}", schema.indexes.len())),
            columns: index_columns,
            unique: true,
        });
    } else {
        return Err(Error::new("unsupported table constraint"));
    }
    Ok(())
}
fn storage_placement(parser: &mut Parser<'_>) -> Result<(), Error> {
    if parser.eat_word("ON") {
        let group = parser.ident()?;
        if !group.eq_ignore_ascii_case("PRIMARY") {
            return Err(Error::new(
                "only PRIMARY installation filegroup is recognized",
            ));
        }
    }
    Ok(())
}
fn create_index(
    parser: &mut Parser<'_>,
    database: &mut ImportedDatabase,
    unique: bool,
) -> Result<(), Error> {
    let name = parser.ident()?;
    parser.expect_word("ON")?;
    let table = parser.object_name()?;
    let table = table_mut(database, &table)?;
    let index_columns = columns(&table.schema, names(parser)?)?;
    table.schema.indexes.push(Index {
        name,
        columns: index_columns,
        unique,
    });
    storage_placement(parser)
}

fn insert_rows(
    parser: &mut Parser<'_>,
    database: &mut ImportedDatabase,
    limits: ImportLimits,
    row_count: &mut usize,
    decoded_bytes: &mut usize,
) -> Result<(), Error> {
    parser.eat_word("INTO");
    let name = parser.object_name()?;
    let table = table_mut(database, &name)?;
    let insert_columns = if parser.peek() == Some(&TokenKind::Symbol('(')) {
        columns(&table.schema, names(parser)?)?
    } else {
        (0..table.schema.columns.len()).collect()
    };
    let mut seen = HashSet::new();
    if insert_columns.iter().any(|column| !seen.insert(*column)) {
        return Err(Error::new("duplicate INSERT column"));
    }
    parser.expect_word("VALUES")?;
    loop {
        let values = parser.group()?;
        let values = split_commas(values);
        if values.len() != insert_columns.len() {
            return Err(Error::new(format!(
                "INSERT into {name:?} has {} values for {} columns",
                values.len(),
                insert_columns.len()
            )));
        }
        let defaults_size = table
            .schema
            .columns
            .iter()
            .filter_map(|column| column.default.as_ref())
            .try_fold(0_usize, |total, value| {
                let size = encode_value(value)?.len();
                if size > limits.max_cell_bytes {
                    return Err(Error::new("default exceeds configured field size limit"));
                }
                total
                    .checked_add(size)
                    .ok_or_else(|| Error::new("default size overflow"))
            })?;
        if decoded_bytes
            .checked_add(defaults_size)
            .is_none_or(|total| total > limits.max_decoded_bytes)
        {
            return Err(Error::new("import exceeds configured decoded byte limit"));
        }
        let mut row = table
            .schema
            .columns
            .iter()
            .map(|column| column.default.clone().unwrap_or(Value::Null))
            .collect::<Row>();
        for (tokens, &column) in values.iter().zip(&insert_columns) {
            let mut value = Parser::new(tokens);
            let literal = value.literal()?;
            if !value.done() {
                return Err(Error::new("INSERT accepts literal field values only"));
            }
            let typed = literal_for_type(&table.schema.columns[column].data_type, &literal)?;
            let field_bytes = encode_value(&typed)?;
            if field_bytes.len() > limits.max_cell_bytes {
                return Err(Error::new("import exceeds configured field size limit"));
            }
            row[column] = typed;
        }
        // SQL Server dump identity values are explicit; unspecified identities are generated.
        for (column, spec) in table.schema.columns.iter().enumerate() {
            if !seen.contains(&column)
                && let Some(identity) = &spec.identity
            {
                let ordinal = i64::try_from(table.rows.len())
                    .map_err(|_| Error::new("identity row count overflow"))?;
                row[column] = Value::Integer(
                    identity
                        .seed
                        .checked_add(
                            identity
                                .increment
                                .checked_mul(ordinal)
                                .ok_or_else(|| Error::new("identity overflow"))?,
                        )
                        .ok_or_else(|| Error::new("identity overflow"))?,
                );
            }
        }
        table.schema.validate_row(&row)?;
        for field in &row {
            let size = encode_value(field)?.len();
            if size > limits.max_cell_bytes {
                return Err(Error::new("import exceeds configured field size limit"));
            }
            *decoded_bytes = decoded_bytes
                .checked_add(size)
                .ok_or_else(|| Error::new("import size overflow"))?;
            if *decoded_bytes > limits.max_decoded_bytes {
                return Err(Error::new("import exceeds configured decoded byte limit"));
            }
        }
        *row_count = row_count
            .checked_add(1)
            .ok_or_else(|| Error::new("row count overflow"))?;
        if *row_count > limits.max_rows {
            return Err(Error::new("import exceeds configured row limit"));
        }
        table.rows.push(row);
        if !parser.eat_symbol(',') {
            break;
        }
    }
    Ok(())
}

fn key(schema: &TableSchema, row: &Row, columns: &[usize]) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    for &column in columns {
        let normalized = match (&schema.columns[column].data_type, &row[column]) {
            (DataType::Text { fixed: true, .. }, Value::Text(text)) => {
                Value::Text(text.trim_end_matches(' ').to_owned())
            }
            (_, Value::Real32(bits)) if f32::from_bits(*bits) == 0.0 => Value::Real32(0),
            (_, Value::Real64(bits)) if f64::from_bits(*bits) == 0.0 => Value::Real64(0),
            (_, other) => other.clone(),
        };
        let encoded = encode_value(&normalized)?;
        bytes.extend(
            u32::try_from(encoded.len())
                .map_err(|_| Error::new("key field too large"))?
                .to_le_bytes(),
        );
        bytes.extend(encoded);
    }
    Ok(bytes)
}
/// Validate explicitly constructed owner input before it can become encrypted genesis.
pub fn validate_database(database: &ImportedDatabase) -> Result<(), Error> {
    if database.name.is_empty() || database.tables.is_empty() {
        return Err(Error::new(
            "database must have a name and at least one table",
        ));
    }
    let mut names = HashSet::new();
    for table in &database.tables {
        if table.schema.name.is_empty() || !names.insert(table.schema.name.to_ascii_lowercase()) {
            return Err(Error::new("empty or duplicate table name"));
        }
        crate::validate_schema(&table.schema)?;
        for row in &table.rows {
            table.schema.validate_row(row)?;
            for &column in &table.schema.primary_key {
                if matches!(row[column], Value::Null) {
                    return Err(Error::new("primary key cannot contain NULL"));
                }
            }
        }
    }
    let mut unique_keys = HashMap::new();
    for (table_id, table) in database.tables.iter().enumerate() {
        let mut definitions = table
            .schema
            .indexes
            .iter()
            .filter(|index| index.unique)
            .map(|index| index.columns.clone())
            .collect::<Vec<_>>();
        if !table.schema.primary_key.is_empty() {
            definitions.push(table.schema.primary_key.clone());
        }
        for columns in definitions {
            let mut keys = HashSet::new();
            for row in &table.rows {
                if !keys.insert(key(&table.schema, row, &columns)?) {
                    return Err(Error::new(format!(
                        "duplicate key in table {:?}",
                        table.schema.name
                    )));
                }
            }
            unique_keys.insert((table_id, columns), keys);
        }
    }
    for table in &database.tables {
        for foreign in &table.schema.foreign_keys {
            let referenced = database
                .tables
                .iter()
                .position(|target| {
                    target
                        .schema
                        .name
                        .eq_ignore_ascii_case(&foreign.referenced_table)
                })
                .ok_or_else(|| {
                    Error::new(format!(
                        "unknown referenced table {:?}",
                        foreign.referenced_table
                    ))
                })?;
            let target = &database.tables[referenced];
            let target_columns = columns(&target.schema, foreign.referenced_columns.clone())?;
            let keys = unique_keys
                .get(&(referenced, target_columns.clone()))
                .ok_or_else(|| {
                    Error::new("foreign key does not reference a declared unique key")
                })?;
            for row in &table.rows {
                if foreign
                    .columns
                    .iter()
                    .any(|&column| matches!(row[column], Value::Null))
                {
                    continue;
                }
                if !keys.contains(&key(&table.schema, row, &foreign.columns)?) {
                    return Err(Error::new(format!(
                        "foreign key violation in table {:?} referencing {:?}",
                        table.schema.name, foreign.referenced_table
                    )));
                }
            }
        }
        for expression in &table.schema.checks {
            validate_check(&table.schema, &table.rows, expression)?;
        }
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Truth {
    True,
    False,
    Unknown,
}
fn validate_check(schema: &TableSchema, rows: &[Row], expression: &str) -> Result<(), Error> {
    let expression = replace_getdate(expression)?;
    let quoted_name = schema.name.replace(']', "]]");
    let plan = crate::plan_select_schemas(
        std::slice::from_ref(schema),
        &format!("SELECT * FROM [{quoted_name}] WHERE {expression}"),
    )?;
    let predicate = plan
        .predicate
        .ok_or_else(|| Error::new("missing CHECK expression"))?;
    for row in rows {
        if check_truth(schema, &predicate, row)? == Truth::False {
            return Err(Error::new(format!(
                "CHECK violation in table {:?}: {expression}",
                schema.name
            )));
        }
    }
    Ok(())
}
fn check_truth(schema: &TableSchema, expr: &crate::Expr, row: &Row) -> Result<Truth, Error> {
    use crate::{CompareOp, Expr};
    use std::cmp::Ordering;
    Ok(match expr {
        Expr::Compare { column, op, value } => {
            let field = &row[*column];
            if matches!(field, Value::Null) || matches!(value, Value::Null) {
                Truth::Unknown
            } else {
                let ordering =
                    crate::compare_typed_values(&schema.columns[*column].data_type, field, value)?;
                let matched = match op {
                    CompareOp::Eq => ordering == Ordering::Equal,
                    CompareOp::Ne => ordering != Ordering::Equal,
                    CompareOp::Lt => ordering == Ordering::Less,
                    CompareOp::Le => ordering != Ordering::Greater,
                    CompareOp::Gt => ordering == Ordering::Greater,
                    CompareOp::Ge => ordering != Ordering::Less,
                };
                if matched { Truth::True } else { Truth::False }
            }
        }
        Expr::IsNull { column, negated } => {
            if matches!(row[*column], Value::Null) != *negated {
                Truth::True
            } else {
                Truth::False
            }
        }
        Expr::Not(expr) => match check_truth(schema, expr, row)? {
            Truth::True => Truth::False,
            Truth::False => Truth::True,
            Truth::Unknown => Truth::Unknown,
        },
        Expr::And(a, b) => match (check_truth(schema, a, row)?, check_truth(schema, b, row)?) {
            (Truth::False, _) | (_, Truth::False) => Truth::False,
            (Truth::True, Truth::True) => Truth::True,
            _ => Truth::Unknown,
        },
        Expr::Or(a, b) => match (check_truth(schema, a, row)?, check_truth(schema, b, row)?) {
            (Truth::True, _) | (_, Truth::True) => Truth::True,
            (Truth::False, Truth::False) => Truth::False,
            _ => Truth::Unknown,
        },
    })
}
fn replace_getdate(expression: &str) -> Result<String, Error> {
    let tokens = lex(expression)?;
    let mut result = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        if tokens[i].kind.word_is("getdate")
            && tokens.get(i + 1).map(|t| &t.kind) == Some(&TokenKind::Symbol('('))
            && tokens.get(i + 2).map(|t| &t.kind) == Some(&TokenKind::Symbol(')'))
        {
            result.push(format!("'{}'", utc_now()?));
            i += 3;
        } else {
            result.push(token_text(&tokens[i..i + 1]));
            i += 1;
        }
    }
    Ok(result.join(" "))
}
fn utc_now() -> Result<String, Error> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::new("system time precedes Unix epoch"))?
        .as_secs();
    let days = (seconds / 86400) as i64;
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    let clock = seconds % 86400;
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}",
        clock / 3600,
        (clock / 60) % 60,
        clock % 60
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn text_constraints_use_column_padding_instead_of_trimming_all_strings() {
        for sql_type in ["VARCHAR(10)", "NVARCHAR(10)", "CHAR(10)", "NCHAR(10)"] {
            let fixed = sql_type.starts_with("CHAR") || sql_type.starts_with("NCHAR");
            let unique = format!(
                "CREATE TABLE labels (label {sql_type} NOT NULL PRIMARY KEY); INSERT INTO labels VALUES ('a'),('a ');"
            );
            let checked = format!(
                "CREATE TABLE labels (label {sql_type} NOT NULL, CHECK(label <> 'a')); INSERT INTO labels VALUES ('a ');"
            );
            for sql in [unique, checked] {
                let result = import_database_dump(&sql, Default::default());
                assert_eq!(result.is_ok(), !fixed, "{sql}: {result:?}");
            }
            let foreign = format!(
                "CREATE TABLE parent (label {sql_type} NOT NULL PRIMARY KEY); CREATE TABLE child (label {sql_type}, FOREIGN KEY(label) REFERENCES parent(label)); INSERT INTO parent VALUES ('a'); INSERT INTO child VALUES ('a ');"
            );
            let result = import_database_dump(&foreign, Default::default());
            assert_eq!(result.is_ok(), fixed, "{foreign}: {result:?}");
        }
    }
    #[test]
    fn import_preserves_typed_unicode_null_binary_and_exact_money() {
        let database=import_database_dump("SET DATEFORMAT mdy\nGO\nCREATE TABLE [Products] ([ProductID] int NOT NULL, [Name] nvarchar(20) NOT NULL, [Price] money NULL, [Born] datetime NULL, [Blob] image NULL, CONSTRAINT PK PRIMARY KEY(ProductID)); INSERT INTO Products VALUES(1,N'Crème d''été',12.3400,'7/4/1996',0x00a1ff),(2,N'海',NULL,NULL,NULL);",Default::default()).unwrap();
        assert_eq!(
            database.tables[0].rows[0],
            vec![
                Value::Integer(1),
                Value::Text("Crème d'été".into()),
                Value::Decimal {
                    unscaled: 123400,
                    scale: 4
                },
                Value::DateTime("1996-07-04T00:00:00".into()),
                Value::Binary(vec![0, 161, 255])
            ]
        );
        assert_eq!(database.tables[0].rows[1][2], Value::Null);
        for row in &database.tables[0].rows {
            let (bytes, ranges) =
                crate::encode_row_with_ranges(&database.tables[0].schema, row).unwrap();
            assert_eq!(
                crate::decode_row(&database.tables[0].schema, &bytes).unwrap(),
                *row
            );
            for (value, range) in row.iter().zip(ranges) {
                assert_eq!(&crate::decode_value(&bytes[range]).unwrap(), value);
            }
        }
    }
    #[test]
    fn row_limit_is_a_resource_configuration_instead_of_128() {
        let mut sql =
            "CREATE TABLE Items(id int NOT NULL PRIMARY KEY, name nvarchar(30) NULL);".to_owned();
        for id in 0..400 {
            sql.push_str(&format!("INSERT INTO Items VALUES({id},N'row {id}');"));
        }
        let database = import_database_dump(&sql, Default::default()).unwrap();
        assert_eq!(database.row_count(), 400);
        assert_eq!(database.tables[0].rows[399][0], Value::Integer(399));
        assert!(
            import_database_dump(
                &sql,
                ImportLimits {
                    max_rows: 399,
                    ..Default::default()
                }
            )
            .unwrap_err()
            .message
            .contains("row limit")
        );
    }
    #[test]
    fn complete_import_validates_primary_foreign_and_check_constraints() {
        let base = "CREATE TABLE Parent(id int NOT NULL PRIMARY KEY); CREATE TABLE Child(id int NOT NULL PRIMARY KEY,parent int NULL,quantity smallint NOT NULL,CONSTRAINT FK FOREIGN KEY(parent) REFERENCES Parent(id),CHECK(quantity > 0)); INSERT INTO Parent VALUES(1);";
        assert!(
            import_database_dump(
                &format!("{base} INSERT INTO Child VALUES(2,1,3);"),
                Default::default()
            )
            .is_ok()
        );
        assert!(
            import_database_dump(
                &format!("{base} INSERT INTO Child VALUES(2,2,3);"),
                Default::default()
            )
            .unwrap_err()
            .message
            .contains("foreign key violation")
        );
        assert!(
            import_database_dump(
                &format!("{base} INSERT INTO Child VALUES(2,1,0);"),
                Default::default()
            )
            .unwrap_err()
            .message
            .contains("CHECK violation")
        );
        assert!(
            import_database_dump(
                &format!("{base} INSERT INTO Parent VALUES(1);"),
                Default::default()
            )
            .unwrap_err()
            .message
            .contains("duplicate key")
        );
    }
    #[test]
    fn stored_programs_are_preserved_and_unknown_mutation_is_rejected() {
        let database=import_database_dump("CREATE TABLE Items(id int NOT NULL);\nGO\nCREATE VIEW Names AS SELECT id FROM Items\nGO\nCREATE PROCEDURE ReadItems AS SELECT * FROM Items\nGO\nINSERT INTO Items VALUES(7)\nGO",Default::default()).unwrap();
        assert_eq!(database.objects.len(), 2);
        assert_eq!(database.row_count(), 1);
        assert!(
            import_database_dump(
                "CREATE TABLE Items(id int NOT NULL); UPDATE Items SET id=8;",
                Default::default()
            )
            .is_err()
        );
    }

    #[test]
    fn malformed_public_empty_schemas_are_rejected_without_panicking() {
        let base = import_database_dump("CREATE TABLE Items(id int NOT NULL);", Default::default())
            .unwrap();
        for invalid in [
            DataType::Integer {
                bits: 0,
                signed: true,
            },
            DataType::Integer {
                bits: 255,
                signed: false,
            },
            DataType::Decimal {
                precision: 255,
                scale: 255,
            },
            DataType::Real { bits: 0 },
            DataType::Text {
                max_chars: Some(usize::MAX),
                unicode: true,
                fixed: true,
            },
            DataType::Binary { max_bytes: Some(0) },
        ] {
            let mut database = base.clone();
            database.tables[0].schema.columns[0].data_type = invalid;
            assert!(validate_database(&database).is_err());
            assert!(crate::plan_select(&database, "SELECT * FROM Items WHERE id = 1").is_err());
            assert!(
                crate::encode_row(&database.tables[0].schema, &vec![Value::Integer(1)]).is_err()
            );
        }
        let mut database = base.clone();
        database.tables[0].schema.primary_key = vec![99];
        assert!(validate_database(&database).is_err());
        let mut database = base;
        database.tables[0].schema.foreign_keys.push(ForeignKey {
            columns: vec![],
            referenced_table: "Items".into(),
            referenced_columns: vec![],
        });
        assert!(validate_database(&database).is_err());
        assert!(
            crate::compare_values(
                &Value::Decimal {
                    unscaled: 1,
                    scale: 255
                },
                &Value::Decimal {
                    unscaled: 1,
                    scale: 0
                }
            )
            .is_err()
        );
    }

    #[test]
    fn defaults_and_nested_comments_obey_import_resource_budgets() {
        let sql = "CREATE TABLE Items(id int NOT NULL DEFAULT(1), label nvarchar(10) NOT NULL DEFAULT('1234567890')); INSERT INTO Items(id) VALUES(1),(2);";
        assert!(
            import_database_dump(
                sql,
                ImportLimits {
                    max_decoded_bytes: 20,
                    ..Default::default()
                }
            )
            .unwrap_err()
            .message
            .contains("byte limit")
        );
        let nested = format!(
            "{}{}CREATE TABLE Items(id int);",
            "/*".repeat(500),
            "*/".repeat(500)
        );
        assert!(
            import_database_dump(&nested, Default::default())
                .unwrap_err()
                .message
                .contains("nesting")
        );
        assert!(
            import_database_dump(
                "IF EXISTS(SELECT * FROM sysobjects) DROP TABLE Items; DELETE FROM Items;",
                Default::default()
            )
            .is_err()
        );
    }
    #[test]
    #[ignore = "requires an explicitly downloaded public Microsoft Northwind script; never vendors the dataset"]
    fn official_northwind_dump_preserves_all_thirteen_tables_and_3308_rows() {
        let path = std::env::var("DCS_NORTHWIND_SQL")
            .expect("set DCS_NORTHWIND_SQL to a downloaded instnwnd.sql");
        let sql = std::fs::read_to_string(path).unwrap();
        let database = import_database_dump(&sql, Default::default()).unwrap();
        let expected = [
            ("Employees", 9),
            ("Categories", 8),
            ("Customers", 91),
            ("Shippers", 3),
            ("Suppliers", 29),
            ("Orders", 830),
            ("Products", 77),
            ("Order Details", 2155),
            ("CustomerCustomerDemo", 0),
            ("CustomerDemographics", 0),
            ("Region", 4),
            ("Territories", 53),
            ("EmployeeTerritories", 49),
        ];
        assert_eq!(database.tables.len(), expected.len());
        for (name, count) in expected {
            assert_eq!(database.table(name).unwrap().rows.len(), count, "{name}");
        }
        assert_eq!(database.row_count(), 3308);
        assert_eq!(
            database.table("Customers").unwrap().rows[0][0],
            Value::Text("ALFKI".into())
        );
        assert!(
            matches!(&database.table("Employees").unwrap().rows[0][14],Value::Binary(bytes) if bytes.len()>1000)
        );
        assert!(database.objects.len() >= 20);
    }
}
