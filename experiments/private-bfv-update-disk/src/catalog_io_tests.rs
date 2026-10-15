// Included inside disk::tests. Public metadata only; generated fixture files contain ciphertext.
#[derive(Default)]
struct CatalogSink {
    bytes: Vec<u8>,
    max_write: usize,
    fail_after: Option<usize>,
    fail_flush: bool,
    flushes: usize,
}
impl Write for CatalogSink {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        if self
            .fail_after
            .is_some_and(|limit| self.bytes.len() >= limit)
        {
            return Err(std::io::Error::other("public fixture write failure"));
        }
        let count = input
            .len()
            .min(if self.max_write == 0 {
                usize::MAX
            } else {
                self.max_write
            })
            .min(
                self.fail_after
                    .map_or(usize::MAX, |limit| limit - self.bytes.len()),
            );
        self.bytes.extend_from_slice(&input[..count]);
        Ok(count)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.flushes += 1;
        if self.fail_flush {
            return Err(std::io::Error::other("public fixture flush failure"));
        }
        Ok(())
    }
}
#[test]
fn buffered_catalog_keeps_exact_original_jsonl_bytes_for_empty_and_escaped_metadata() {
    let (mut entry, _data, _index) = entry();
    entry.data_path = PathBuf::from("public-quote\"-backslash\\-unicode-Ж.bin");
    let entries = [entry];
    for catalog in [&entries[..0], &entries[..]] {
        let mut expected = Vec::new();
        for entry in catalog {
            serde_json::to_writer(&mut expected, &entry.record()).unwrap();
            expected.write_all(b"\n").unwrap();
        }
        for capacity in [1, 7, CATALOG_BUFFER_BYTES] {
            let mut actual = CatalogSink {
                max_write: 3,
                ..CatalogSink::default()
            };
            {
                let mut buffered = BufWriter::with_capacity(capacity, &mut actual);
                write_catalog(&mut buffered, catalog, None).unwrap();
            }
            assert_eq!(actual.bytes, expected);
            assert!(actual.flushes > 0);
        }
    }
}
#[test]
fn buffered_catalog_propagates_tail_write_and_inner_flush_errors() {
    let (entry, _data, _index) = entry();
    let catalog = [entry];
    for (fail_after, fail_flush, capacity) in [
        (Some(3), false, CATALOG_BUFFER_BYTES),
        (Some(3), false, 7),
        (None, true, CATALOG_BUFFER_BYTES),
    ] {
        let mut sink = CatalogSink {
            fail_after,
            fail_flush,
            ..CatalogSink::default()
        };
        let mut buffered = BufWriter::with_capacity(capacity, &mut sink);
        assert!(write_catalog(&mut buffered, &catalog, None).is_err());
    }
}
#[test]
fn catalog_projection_serializes_new_heads_without_publishing_live_owner_state() {
    let (entry, _data, _index) = entry();
    let old_data = entry.data_head.clone();
    let old_index = entry.index_head.clone();
    let mut staged_data = EncryptedSnapshot::decode(
        &read_exact_image(&entry.data_path, entry.data_len, MAX_SINGLE_IMAGE).unwrap(),
        Limits::default(),
    )
    .unwrap();
    let new_data = entry
        .owner
        .replace_page(
            &mut staged_data,
            &old_data,
            0,
            &[250, 101, 0],
            Limits::default(),
        )
        .unwrap();
    let catalog = [entry];
    let mut wire = Vec::new();
    write_catalog(
        &mut wire,
        &catalog,
        Some(&CatalogProjection {
            id: 0,
            data: &new_data,
            index: &old_index,
        }),
    )
    .unwrap();
    let actual: serde_json::Value = serde_json::from_slice(&wire).unwrap();
    assert_eq!(actual["data_head_hex"], hex(&new_data.encode()));
    assert_eq!(catalog[0].data_head, old_data);
    assert_eq!(catalog[0].index_head, old_index);
}
