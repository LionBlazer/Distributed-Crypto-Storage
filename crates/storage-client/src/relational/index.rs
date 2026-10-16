use super::*;
use relational_types::{
    CompareOp, DataType, Expr, ImportedTable, SelectPlan, compare_typed_values,
};
use std::{cmp::Ordering, collections::BTreeSet};

type Set = BTreeSet<usize>;
fn ordered(data_type: &DataType, a: &Value, b: &Value) -> Ordering {
    match (a, b) {
        (Value::Null, Value::Null) => Ordering::Equal,
        (Value::Null, _) => Ordering::Less,
        (_, Value::Null) => Ordering::Greater,
        _ => compare_typed_values(data_type, a, b).expect("same validated column type"),
    }
}

impl PrivateIndex {
    pub(super) fn build(table: ImportedTable) -> Result<(Zeroizing<Vec<u8>>, Self)> {
        let mut bytes = Zeroizing::new(Vec::new());
        let mut cells = Vec::new();
        let mut maps =
            vec![BTreeMap::<Vec<u8>, (Value, Vec<usize>)>::new(); table.schema.columns.len()];
        for (ordinal, row) in table.rows.into_iter().enumerate() {
            table.schema.validate_row(&row).map_err(invalid)?;
            let mut positions = Vec::new();
            for (column, value) in row.into_iter().enumerate() {
                let encoded = relational_types::encode_value(&value).map_err(invalid)?;
                positions.push(Cell {
                    offset: bytes.len(),
                    length: encoded.len(),
                });
                bytes.extend_from_slice(&encoded);
                maps[column]
                    .entry(encoded)
                    .or_insert_with(|| (value, Vec::new()))
                    .1
                    .push(ordinal);
            }
            cells.push(positions);
            if bytes.len() > MAX_TABLE_BYTES {
                return Err(invalid(
                    "Table exceeds the configured 8 MiB encoded-cell budget; split the import into bounded relations",
                ));
            }
        }
        let columns = maps
            .into_iter()
            .enumerate()
            .map(|(column, map)| {
                let mut postings: Vec<_> = map
                    .into_values()
                    .map(|(value, rows)| Posting { value, rows })
                    .collect();
                postings.sort_by(|a, b| {
                    ordered(&table.schema.columns[column].data_type, &a.value, &b.value)
                });
                postings
            })
            .collect();
        let index = Self {
            format: 3,
            schema: table.schema,
            cells,
            columns,
            data_bytes: bytes.len(),
            catalog_objects: Vec::new(),
            import_notices: Vec::new(),
        };
        Ok((bytes, index))
    }

    pub(super) fn validate(&self, schema: &TableSchema, bytes: usize) -> Result<()> {
        if self.format != 3
            || &self.schema != schema
            || self.data_bytes != bytes
            || self.columns.len() != schema.columns.len()
        {
            return Err(crypto(
                "Typed private index disagrees with the committed table schema",
            ));
        }
        let mut offset = 0;
        for row in &self.cells {
            if row.len() != schema.columns.len() {
                return Err(crypto("Incomplete indexed row"));
            }
            for cell in row {
                if cell.offset != offset || cell.length == 0 {
                    return Err(crypto("Missing or overlapping indexed cell"));
                }
                offset = offset
                    .checked_add(cell.length)
                    .ok_or_else(|| crypto("Cell range overflow"))?;
            }
        }
        if offset != bytes {
            return Err(crypto("Incomplete indexed byte coverage"));
        }
        for (column, postings) in self.columns.iter().enumerate() {
            let mut seen = Set::new();
            let mut values = BTreeSet::new();
            for posting in postings {
                if posting.rows.is_empty() || !values.insert(json(&posting.value)?) {
                    return Err(crypto("Duplicate or empty index posting"));
                }
                for ordinal in &posting.rows {
                    if *ordinal >= self.cells.len() || !seen.insert(*ordinal) {
                        return Err(crypto("Duplicate or invalid indexed ordinal"));
                    }
                }
            }
            if postings.windows(2).any(|pair| {
                ordered(
                    &schema.columns[column].data_type,
                    &pair[0].value,
                    &pair[1].value,
                ) == Ordering::Greater
            }) {
                return Err(crypto("Unsorted private index"));
            }
            if seen.len() != self.cells.len() {
                return Err(crypto("Index does not cover every row exactly once"));
            }
        }
        Ok(())
    }

    fn matching(&self, expr: &Expr, negate: bool) -> Result<Set> {
        match expr {
            Expr::Compare { column, op, value } => {
                if matches!(value, Value::Null) {
                    return Ok(Set::new());
                }
                let postings = &self.columns[*column];
                let data_type = &self.schema.columns[*column].data_type;
                let first = postings.partition_point(|p| matches!(p.value, Value::Null));
                let postings = &postings[first..];
                let lower = postings
                    .partition_point(|p| ordered(data_type, &p.value, value) == Ordering::Less);
                let upper = postings
                    .partition_point(|p| ordered(data_type, &p.value, value) != Ordering::Greater);
                let op = if negate {
                    match op {
                        CompareOp::Eq => CompareOp::Ne,
                        CompareOp::Ne => CompareOp::Eq,
                        CompareOp::Lt => CompareOp::Ge,
                        CompareOp::Le => CompareOp::Gt,
                        CompareOp::Gt => CompareOp::Le,
                        CompareOp::Ge => CompareOp::Lt,
                    }
                } else {
                    *op
                };
                let slices: Vec<&[Posting]> = match op {
                    CompareOp::Eq => vec![&postings[lower..upper]],
                    CompareOp::Ne => vec![&postings[..lower], &postings[upper..]],
                    CompareOp::Lt => vec![&postings[..lower]],
                    CompareOp::Le => vec![&postings[..upper]],
                    CompareOp::Gt => vec![&postings[upper..]],
                    CompareOp::Ge => vec![&postings[lower..]],
                };
                Ok(slices
                    .into_iter()
                    .flatten()
                    .flat_map(|p| p.rows.iter().copied())
                    .collect())
            }
            Expr::IsNull { column, negated } => {
                let postings = &self.columns[*column];
                let boundary = postings.partition_point(|p| matches!(p.value, Value::Null));
                let selected = if *negated != negate {
                    &postings[boundary..]
                } else {
                    &postings[..boundary]
                };
                Ok(selected
                    .iter()
                    .flat_map(|p| p.rows.iter().copied())
                    .collect())
            }
            Expr::Not(inner) => self.matching(inner, !negate),
            Expr::And(left, right) | Expr::Or(left, right) => {
                let a = self.matching(left, negate)?;
                let b = self.matching(right, negate)?;
                if matches!(expr, Expr::And(..)) != negate {
                    Ok(a.intersection(&b).copied().collect())
                } else {
                    Ok(a.union(&b).copied().collect())
                }
            }
        }
    }

    pub(super) fn select(&self, plan: &SelectPlan) -> Result<Vec<usize>> {
        if plan.window.with_ties && plan.order_by.is_empty() {
            return Err(invalid("FETCH WITH TIES requires ORDER BY"));
        }
        let mut rows: Vec<_> = match &plan.predicate {
            Some(expr) => self.matching(expr, false)?.into_iter().collect(),
            None => (0..self.cells.len()).collect(),
        };
        let mut ordered = Vec::new();
        for order in &plan.order_by {
            let mut by_row = vec![&Value::Null; self.cells.len()];
            for posting in &self.columns[order.column] {
                for row in &posting.rows {
                    by_row[*row] = &posting.value;
                }
            }
            ordered.push(by_row);
        }
        // The physical ordinal makes otherwise equal rows deterministic, but
        // it must not split SQL peer groups when extending FETCH WITH TIES.
        let compare_keys = |left: usize, right: usize| {
            for (i, order) in plan.order_by.iter().enumerate() {
                let a = ordered[i][left];
                let b = ordered[i][right];
                let cmp = match (a, b) {
                    (Value::Null, Value::Null) => Ordering::Equal,
                    (Value::Null, _) if order.nulls_first => Ordering::Less,
                    (Value::Null, _) => Ordering::Greater,
                    (_, Value::Null) if order.nulls_first => Ordering::Greater,
                    (_, Value::Null) => Ordering::Less,
                    _ => {
                        let cmp = compare_typed_values(
                            &self.schema.columns[order.column].data_type,
                            a,
                            b,
                        )
                        .expect("validated same-typed complete index");
                        if order.descending { cmp.reverse() } else { cmp }
                    }
                };
                if cmp != Ordering::Equal {
                    return cmp;
                }
            }
            Ordering::Equal
        };
        if !plan.order_by.is_empty() {
            rows.sort_by(|left, right| compare_keys(*left, *right).then(left.cmp(right)));
        }
        let start = plan.window.offset.min(rows.len());
        let mut end = plan.window.limit.map_or(rows.len(), |limit| {
            start.saturating_add(limit).min(rows.len())
        });
        if plan.window.with_ties && end > start {
            while end < rows.len() && compare_keys(rows[end - 1], rows[end]) == Ordering::Equal {
                end += 1;
            }
        }
        rows.truncate(end);
        rows.drain(..start);
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn relation() -> ImportedTable {
        relational_types::import_database_dump("CREATE TABLE things (id INT NOT NULL, name NVARCHAR(20) NULL); INSERT INTO things VALUES (1,'one'),(2,NULL),(3,'three');", relational_types::ImportLimits::default()).unwrap().tables.remove(0)
    }
    #[test]
    fn old_or_unknown_typed_index_versions_and_check_language_changes_fail_closed() {
        let (bytes, mut index) = PrivateIndex::build(relation()).unwrap();
        assert_eq!(index.format, 3);
        for format in [2, 4, u32::MAX] {
            index.format = format;
            let decoded: PrivateIndex = serde_json::from_slice(&json(&index).unwrap()).unwrap();
            assert!(decoded.validate(&decoded.schema, bytes.len()).is_err());
        }
        let mut pg = index.schema.clone();
        pg.checks
            .push(relational_types::CheckConstraint::PostgreSql18Utf8 {
                source: "id > 0".into(),
            });
        let mut source = pg.clone();
        source.checks[0] = relational_types::CheckConstraint::SqlServerDumpAsciiCi {
            source: "id > 0".into(),
        };
        assert_ne!(
            schema_id(&pg, false).unwrap(),
            schema_id(&source, false).unwrap()
        );
        assert_ne!(
            schema_id(&pg, true).unwrap(),
            schema_id(&source, true).unwrap()
        );
    }
    #[test]
    fn complete_postings_handle_sql_unknown_and_deterministic_order_without_reading_rows() {
        let (bytes, index) = PrivateIndex::build(relation()).unwrap();
        index.validate(&index.schema, bytes.len()).unwrap();
        for (sql, expected) in [
            ("SELECT id FROM things WHERE NOT (name = 'one')", vec![2]),
            (
                "SELECT id FROM things WHERE name IS NULL OR id >= 3 ORDER BY id DESC",
                vec![2, 1],
            ),
        ] {
            let plan =
                relational_types::plan_select_schemas(std::slice::from_ref(&index.schema), sql)
                    .unwrap();
            assert_eq!(index.select(&plan).unwrap(), expected);
        }
    }
    #[test]
    fn variable_text_spaces_remain_significant_while_fixed_char_padding_does_not() {
        let table = relational_types::import_database_dump(
            "CREATE TABLE labels (id INT NOT NULL, variable VARCHAR(10), fixed CHAR(10)); INSERT INTO labels VALUES (1,'a ','a '),(2,'a','a'),(3,'a  ','a  '),(4,NULL,NULL),(5,'a\t','a\t');",
            relational_types::ImportLimits::default(),
        )
        .unwrap()
        .tables
        .remove(0);
        let (bytes, index) = PrivateIndex::build(table).unwrap();
        index.validate(&index.schema, bytes.len()).unwrap();
        for (tail, expected) in [
            ("WHERE variable = 'a'", vec![1]),
            ("WHERE variable = 'a '", vec![0]),
            ("WHERE variable > 'a' ORDER BY variable", vec![4, 0, 2]),
            (
                "WHERE variable <> 'a' ORDER BY variable DESC LIMIT 1",
                vec![2],
            ),
            ("WHERE fixed = 'a' ORDER BY id", vec![0, 1, 2]),
            ("WHERE fixed > 'a'", vec![4]),
            ("ORDER BY fixed, id", vec![0, 1, 2, 4, 3]),
            ("ORDER BY fixed FETCH FIRST ROW WITH TIES", vec![0, 1, 2]),
            (
                "ORDER BY fixed OFFSET 1 FETCH NEXT ROW WITH TIES",
                vec![1, 2],
            ),
            ("ORDER BY variable", vec![1, 4, 0, 2, 3]),
        ] {
            let sql = format!("SELECT id FROM labels {tail}");
            let plan =
                relational_types::plan_select_schemas(std::slice::from_ref(&index.schema), &sql)
                    .unwrap();
            assert_eq!(index.select(&plan).unwrap(), expected, "{sql}");
        }
    }
    #[test]
    fn missing_duplicate_or_overlapping_index_entries_are_rejected() {
        let (bytes, mut index) = PrivateIndex::build(relation()).unwrap();
        index.columns[0][0].rows.push(1);
        assert!(index.validate(&index.schema, bytes.len()).is_err());
        let (bytes, mut index) = PrivateIndex::build(relation()).unwrap();
        index.cells[0][0].length += 1;
        assert!(index.validate(&index.schema, bytes.len()).is_err());
        let (bytes, mut index) = PrivateIndex::build(relation()).unwrap();
        index.format = 1;
        assert!(index.validate(&index.schema, bytes.len()).is_err());
    }

    #[test]
    fn null_placement_is_per_sort_key_and_precedes_the_limit() {
        let table = relational_types::import_database_dump(
            "CREATE TABLE ranks (id INT NOT NULL, score INT NULL); INSERT INTO ranks VALUES (1,NULL),(2,10),(3,-5),(4,NULL),(5,10);",
            relational_types::ImportLimits::default(),
        )
        .unwrap()
        .tables
        .remove(0);
        let (bytes, index) = PrivateIndex::build(table).unwrap();
        index.validate(&index.schema, bytes.len()).unwrap();
        for (tail, expected) in [
            ("ORDER BY score", vec![2, 1, 4, 0, 3]),
            ("ORDER BY score DESC", vec![0, 3, 1, 4, 2]),
            ("ORDER BY score ASC NULLS FIRST", vec![0, 3, 2, 1, 4]),
            ("ORDER BY score DESC NULLS LAST", vec![1, 4, 2, 0, 3]),
            ("ORDER BY score NULLS FIRST, id DESC", vec![3, 0, 2, 4, 1]),
            (
                "ORDER BY score NULLS FIRST, id DESC, score DESC NULLS LAST",
                vec![3, 0, 2, 4, 1],
            ),
            ("ORDER BY score LIMIT 1", vec![2]),
            ("WHERE score IS NULL ORDER BY id DESC", vec![3, 0]),
            ("WHERE score <> 10 ORDER BY score", vec![2]),
        ] {
            let sql = format!("SELECT id FROM ranks {tail}");
            let plan =
                relational_types::plan_select_schemas(std::slice::from_ref(&index.schema), &sql)
                    .unwrap();
            assert_eq!(index.select(&plan).unwrap(), expected, "{sql}");
        }
    }
}
