//! Measure serialized storage using public synthetic rows and the prototype API.
#[path = "../src/metrics.rs"]
mod metrics;

use fhe_prototype::{Owner, PlainRow};
use serde::Serialize;
use std::time::Instant;

#[derive(Serialize)]
struct Measurement {
    rows: usize,
    logical_plaintext_bytes: usize,
    compressed_image_bytes: usize,
    expansion: Option<f64>,
    encryption_ms: f64,
    compression_ms: f64,
    process_peak_resident_bytes: Option<u64>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    rayon::ThreadPoolBuilder::new()
        .num_threads(2)
        .build_global()?;
    let (owner, evaluator) = Owner::generate()?;
    for rows in [0, 4, 16, 64, 256, 1024] {
        let fixture: Vec<_> = (0..rows)
            .map(|index| PlainRow {
                age: (index % 256) as u8,
                amount: ((index * 137) % 65536) as u16,
            })
            .collect();
        let timer = Instant::now();
        let table = owner.encrypt_table(&fixture)?;
        let encryption_ms = timer.elapsed().as_secs_f64() * 1000.0;
        let timer = Instant::now();
        let image = evaluator.compress_table(&table)?;
        let logical_plaintext_bytes = rows * 3;
        let measurement = Measurement {
            rows,
            logical_plaintext_bytes,
            compressed_image_bytes: image.len(),
            expansion: (rows != 0).then(|| image.len() as f64 / logical_plaintext_bytes as f64),
            encryption_ms,
            compression_ms: timer.elapsed().as_secs_f64() * 1000.0,
            process_peak_resident_bytes: metrics::peak_resident_bytes(),
        };
        println!("{}", serde_json::to_string(&measurement)?);
    }
    Ok(())
}
