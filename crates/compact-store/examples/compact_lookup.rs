//! Public varied 3-byte fixture, ephemeral owner key, no output data/key files.
//! This measures authenticated retrieval + owner decryption, never FHE SQL.
use compact_store::{
    EncryptedSnapshot, Layout, Limits, LookupResponse, MANIFEST_BYTES, Owner, PAGE_OVERHEAD,
};
use serde_json::json;
use std::time::Instant;

fn fixture(count: usize) -> Vec<u8> {
    (0..count)
        .flat_map(|i| {
            let age = ((i * 37 + (i >> 8) * 17 + 11) % 256) as u8;
            let amount = ((i * 719 + (i >> 16) * 927 + 123) % 65_536) as u16;
            [age, amount as u8, (amount >> 8) as u8]
        })
        .collect()
}

fn layout(rows: u64) -> Layout {
    Layout {
        schema: *b"age8/amount16-v1",
        row_width: 3,
        rows_per_page: 256,
        row_count: rows,
    }
}

fn percentile(values: &[f64], percentile: usize) -> f64 {
    values[((values.len() - 1) * percentile).div_ceil(100)]
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let row_count: u64 = args
        .next()
        .map(|v| v.parse())
        .transpose()?
        .unwrap_or(1_000_000);
    let rounds: usize = args.next().map(|v| v.parse()).transpose()?.unwrap_or(1000);
    let replacements: u64 = args.next().map(|v| v.parse()).transpose()?.unwrap_or(1000);
    if row_count == 0 || rounds == 0 || rounds > 1_000_000 || replacements > 1_000_000 {
        return Err(
            "positive row/round counts and at most one million rounds/replacements required".into(),
        );
    }
    let limits = Limits::default();
    layout(row_count).validate(limits)?;
    let owner = Owner::generate(*b"public-bench-db!")?;

    for rows in [0, 1, 16, 64, 1024, 65_536, row_count] {
        let plain = fixture(rows as usize);
        let start = Instant::now();
        let snapshot = owner.seal(layout(rows), &plain, limits)?;
        let seal_ms = start.elapsed().as_secs_f64() * 1000.0;
        let image = snapshot.encode();
        assert_eq!(
            image.len(),
            MANIFEST_BYTES + plain.len() + layout(rows).page_count()? * PAGE_OVERHEAD
        );
        let restored = EncryptedSnapshot::decode(&image, limits)?;
        assert_eq!(restored.commitment(), snapshot.commitment());
        println!(
            "{}",
            json!({
                "experiment": "compact-page-storage",
                "logical_rows": rows, "logical_row_bytes": 3, "logical_bytes": plain.len(),
                "canonical_image_bytes": image.len(),
                "manifest_bytes": MANIFEST_BYTES, "page_overhead_bytes": PAGE_OVERHEAD,
                "pages": layout(rows).page_count()?, "padding_bytes": 0,
                "storage_expansion": if plain.is_empty() { None } else { Some(image.len() as f64 / plain.len() as f64) },
                "rebuildable_index_hash_bytes": snapshot.index_hash_bytes(),
                "image_plus_index_hash_bytes": image.len() + snapshot.index_hash_bytes(),
                "owner_key_bytes_excluded": 32, "replicas": 1, "seal_ms": seal_ms,
                "contains_fhe": false, "contains_sql_query_proof": false,
            })
        );
    }

    let mut plain = fixture(row_count as usize);
    let mut peer = owner.seal(layout(row_count), &plain, limits)?;
    let initial_image_bytes = peer.encoded_len();
    let initial_index_bytes = peer.index_hash_bytes();
    let old_head = peer.commitment().clone();
    let old_proof = peer.lookup(0, limits)?;
    let mut trusted = old_head.clone();
    let mut latency_us = Vec::with_capacity(rounds);
    let mut response_bytes = 0;
    for round in 0..rounds {
        let row = ((round as u64 * 104_729 + 13) % row_count) as usize;
        let start = Instant::now();
        let address = trusted.layout().address_of(row as u64)?;
        let response = peer.lookup(address.page_index, limits)?;
        let wire = response.encode();
        response_bytes = wire.len();
        let received = LookupResponse::decode(&wire, limits)?;
        let verified = received.verify(&trusted, address.page_index, limits)?;
        let plaintext = owner.decrypt(&verified)?;
        let result = &plaintext.as_bytes()[address.byte_offset..address.byte_offset + 3];
        latency_us.push(start.elapsed().as_secs_f64() * 1_000_000.0);
        assert_eq!(result, &plain[row * 3..row * 3 + 3]);
    }
    latency_us.sort_by(f64::total_cmp);
    let image = peer.encode();
    let cold_start = Instant::now();
    let cold_peer = EncryptedSnapshot::decode(&image, limits)?;
    let cold_response = cold_peer.lookup(0, limits)?;
    let cold_page = cold_response.verify(&trusted, 0, limits)?;
    let cold_plain = owner.decrypt(&cold_page)?;
    assert_eq!(&cold_plain.as_bytes()[..3], &plain[..3]);
    let cold_restore_lookup_us = cold_start.elapsed().as_secs_f64() * 1_000_000.0;
    drop(cold_peer);
    drop(image);

    let start = Instant::now();
    for revision in 1..=replacements {
        let page_index = (revision * 37) % layout(row_count).page_count()? as u64;
        let first_row = page_index as usize * 256;
        let first = first_row * 3;
        let end = (first + 256 * 3).min(plain.len());
        plain[first] = plain[first].wrapping_add(1);
        trusted =
            owner.replace_page(&mut peer, &trusted, page_index, &plain[first..end], limits)?;
        assert_eq!(peer.encoded_len(), initial_image_bytes);
        assert_eq!(peer.index_hash_bytes(), initial_index_bytes);
        let response = peer.lookup(page_index, limits)?;
        let verified = response.verify(&trusted, page_index, limits)?;
        assert_eq!(owner.decrypt(&verified)?.as_bytes(), &plain[first..end]);
    }
    let replacement_ms = start.elapsed().as_secs_f64() * 1000.0;
    let restored = EncryptedSnapshot::decode(&peer.encode(), limits)?;
    assert_eq!(restored.commitment(), &trusted);
    if replacements > 0 {
        assert!(old_proof.verify(&trusted, 0, limits).is_err());
    }
    println!(
        "{}",
        json!({
            "experiment": "authenticated-address-lookup-owner-decryption",
            "logical_rows": row_count, "rows_per_page": 256,
            "latency_samples": rounds,
            "warm_p50_us": percentile(&latency_us, 50),
            "warm_p95_us": percentile(&latency_us, 95),
            "warm_p99_us": percentile(&latency_us, 99),
            "cold_image_restore_and_one_lookup_us": cold_restore_lookup_us,
            "last_response_bytes": response_bytes, "replacements": replacements,
            "replacement_verify_ms_total": replacement_ms,
            "canonical_image_before_bytes": initial_image_bytes,
            "canonical_image_after_bytes": peer.encoded_len(),
            "rebuildable_index_hash_bytes": peer.index_hash_bytes(),
            "current_revision": trusted.revision(),
            "stale_root_replay_rejected": replacements > 0,
            "privacy": "observable-page-address-and-repetition",
            "network_consensus_and_fhe_excluded": true,
            "owner_key_and_plaintext_stay_client_side": true,
            "contains_fhe": false, "contains_sql_query_proof": false,
        })
    );
    Ok(())
}
