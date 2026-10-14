//! Every record/seed here is intentionally public and non-secret.
use spiral_cache_core::{
    CACHE_BYTES, Error, RECORD_BYTES, RECORD_IMAGE_BYTES, load_pair, load_records, profile_params,
};
use spiral_rs::{
    client::{Client, PublicParameters, Query},
    server::{load_db_from_seek, process_query},
};
use std::io::Cursor;
fn records(tag: u8) -> Vec<u8> {
    (0..RECORD_IMAGE_BYTES)
        .map(|i| (i.wrapping_mul(13).wrapping_add(i / 97) as u8).wrapping_add(tag))
        .collect()
}
#[test]
fn changed_profile_is_rejected_before_conversion() {
    let mut params = profile_params();
    params.db_dim_1 = 6;
    assert!(matches!(
        load_records(&params, &[]),
        Err(Error::UnsupportedProfile)
    ));
}
#[test]
fn short_and_extended_record_images_are_rejected_instead_of_zero_padded() {
    let params = profile_params();
    for size in [0, RECORD_IMAGE_BYTES - 1, RECORD_IMAGE_BYTES + 1] {
        let data = vec![0; size];
        assert!(
            matches!(load_records(&params, &data), Err(Error::RecordImageLength { actual, .. }) if actual == size)
        );
    }
}
#[test]
fn invalid_second_input_is_rejected_before_pair_conversion() {
    let params = profile_params();
    let data = records(1);
    assert!(matches!(
        load_pair(&params, &data, &[]),
        Err(Error::RecordImageLength { actual: 0, .. })
    ));
}
#[test]
fn all_native_words_match_the_original_serial_loader_for_distinct_inputs() {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(8)
        .build()
        .unwrap();
    pool.install(|| {
        let params = profile_params();
        let data = records(1);
        let index = records(73);
        let expected_data = load_db_from_seek(&params, &mut Cursor::new(&data));
        let expected_index = load_db_from_seek(&params, &mut Cursor::new(&index));
        let (actual_data, actual_index) = load_pair(&params, &data, &index).unwrap();
        assert_eq!(actual_data.len() * 8, CACHE_BYTES);
        assert_eq!(actual_data.as_slice(), expected_data.as_slice());
        assert_eq!(actual_index.as_slice(), expected_index.as_slice());
        assert_ne!(actual_data.as_slice(), actual_index.as_slice());
    });
}
#[test]
fn real_native_pir_reads_recover_first_middle_last_from_parallel_cache() {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(8)
        .build()
        .unwrap();
    pool.install(|| {
        let params = profile_params();
        let bytes = records(7);
        let cache = load_records(&params, &bytes).unwrap();
        let mut client = Client::init(&params);
        let original = client.generate_keys();
        let public = PublicParameters::deserialize(&params, &original.serialize());
        for item in [0, 256, 511] {
            let wire = client.generate_query(item).serialize();
            let query = Query::deserialize(&params, &wire);
            let answer = process_query(&params, &public, &query, cache.as_slice());
            let actual = client.decode_response(&answer);
            assert_eq!(actual.len(), RECORD_BYTES + 32);
            assert_eq!(
                &actual[..RECORD_BYTES],
                &bytes[item * RECORD_BYTES..(item + 1) * RECORD_BYTES]
            );
            assert!(actual[RECORD_BYTES..].iter().all(|v| *v == 0));
        }
    });
}
