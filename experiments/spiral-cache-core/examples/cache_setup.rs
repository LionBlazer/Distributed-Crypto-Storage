//! Fresh-process, public-record paired conversion benchmark; no key files or secrets.
#[path = "support/memory.rs"]
mod memory;
use serde_json::json;
use spiral_cache_core::{CACHE_BYTES, RECORD_IMAGE_BYTES, load_pair, profile_params};
use spiral_rs::server::load_db_from_seek;
use std::{io::Cursor, time::Instant};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mode = std::env::args()
        .nth(1)
        .ok_or("Use cache_setup <serial|parallel>")?;
    if !["serial", "parallel"].contains(&mode.as_str()) {
        return Err("Unknown mode".into());
    }
    rayon::ThreadPoolBuilder::new()
        .num_threads(8)
        .build_global()?;
    let params = profile_params();
    let data: Vec<_> = (0..RECORD_IMAGE_BYTES)
        .map(|i| (i.wrapping_mul(13).wrapping_add(i / 97)) as u8)
        .collect();
    let index: Vec<_> = data.iter().map(|v| v.wrapping_add(73)).collect();
    memory::guard(160 * 1024 * 1024)?;
    let start = Instant::now();
    let (data_cache, index_cache) = if mode == "serial" {
        (
            load_db_from_seek(&params, &mut Cursor::new(&data)),
            load_db_from_seek(&params, &mut Cursor::new(&index)),
        )
    } else {
        load_pair(&params, &data, &index)?
    };
    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(data_cache.len() * 8, CACHE_BYTES);
    assert_eq!(index_cache.len() * 8, CACHE_BYTES);
    println!(
        "{}",
        json!({"experiment":"spiral-pair-cache-setup", "mode":mode,"whole_pair_ms":elapsed,
        "record_images_bytes":2*RECORD_IMAGE_BYTES,"retained_ntt_cache_bytes":2*CACHE_BYTES,
        "rayon_threads":8,"native_memory":memory::guard(0)?,"sdk_revision":"fdb7206517c249603b0c91b65f1f29f95272107c",
        "not_query_latency":true,"cache_outputs_written":false})
    );
    Ok(())
}
