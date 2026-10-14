mod metrics;

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use fhe_prototype::{Comparison, EncryptedTable, Evaluator, MAX_ROWS, Owner, PlainRow};
use serde::Serialize;

type AppResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug)]
struct Options {
    rows: usize,
    cycles: usize,
    min_age: u8,
    delta: u16,
    threads: usize,
    output_dir: PathBuf,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            rows: 4,
            cycles: 2,
            min_age: 18,
            delta: 5,
            threads: 2,
            output_dir: PathBuf::from(".local/fhe-runs"),
        }
    }
}

#[derive(Serialize)]
struct Aggregate {
    count: u32,
    sum: u32,
}

#[derive(Serialize)]
struct Cycle {
    cycle: usize,
    update_ms: f64,
    update_rejected: bool,
    compression_write_reload_ms: f64,
    query_and_decrypt_ms: f64,
    compressed_table_bytes: u64,
    aggregate: Aggregate,
}

#[derive(Serialize)]
struct Report {
    experiment: &'static str,
    result_status: &'static str,
    crate_version: &'static str,
    tfhe_version: &'static str,
    parameters: &'static str,
    os: &'static str,
    architecture: &'static str,
    available_parallelism: usize,
    rayon_threads: usize,
    rows: usize,
    min_age: u8,
    update_delta: u16,
    logical_plaintext_bytes: usize,
    evaluation_key_serialized_bytes: u64,
    key_generation_ms: f64,
    encryption_ms: f64,
    initial_compression_write_reload_ms: f64,
    initial_query_and_decrypt_ms: f64,
    initial_compressed_table_bytes: u64,
    initial_aggregate: Aggregate,
    cycles: Vec<Cycle>,
    compressed_table_to_plaintext_ratio: Option<f64>,
    process_peak_resident_bytes: Option<u64>,
    total_experiment_ms: f64,
    artifact_directory: String,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> AppResult<()> {
    let Some(options) = parse_options(std::env::args().skip(1))? else {
        return Ok(());
    };
    if cfg!(debug_assertions) {
        return Err(
            "FHE measurements require --release: cargo run --release -p fhe-prototype".into(),
        );
    }
    rayon::ThreadPoolBuilder::new()
        .num_threads(options.threads)
        .build_global()?;
    let directory = create_run_directory(&options.output_dir)?;
    let table_path = directory.join("table.fhe");
    let total = Instant::now();

    eprintln!(
        "Generating ephemeral FHE keys ({} Rayon threads)...",
        options.threads
    );
    let timer = Instant::now();
    let (owner, evaluator) = Owner::generate()?;
    let key_generation_ms = elapsed_ms(timer);
    let evaluation_key_serialized_bytes = evaluator.evaluation_key_serialized_bytes()?;

    // The fixture is deliberately public and synthetic, never participant data.
    let mut expected_rows = fixture(options.rows);
    let timer = Instant::now();
    let table = owner.encrypt_table(&expected_rows)?;
    let predicate = owner.encrypt_predicate(Comparison::AtLeast, options.min_age)?;
    let delta = owner.encrypt_delta(options.delta)?;
    let encryption_ms = elapsed_ms(timer);

    let timer = Instant::now();
    let (mut table, initial_bytes) = write_and_reload(&evaluator, table, &table_path)?;
    let initial_compression_write_reload_ms = elapsed_ms(timer);
    let timer = Instant::now();
    let initial =
        owner.decrypt_aggregate_for_experiment(&evaluator.aggregate(&table, &predicate)?)?;
    let initial_query_and_decrypt_ms = elapsed_ms(timer);
    check_aggregate(initial, &expected_rows, options.min_age)?;

    let mut cycles = Vec::with_capacity(options.cycles);
    let mut final_bytes = initial_bytes;
    for cycle in 1..=options.cycles {
        eprintln!(
            "Update / compress / reload / query cycle {cycle}/{}...",
            options.cycles
        );
        let timer = Instant::now();
        let update = evaluator.add_amount(&mut table, &predicate, &delta)?;
        let rejected = owner.decrypt_update_rejection_for_experiment(&update)?;
        let update_ms = elapsed_ms(timer);
        let expected_rejected = expected_rows.iter().any(|row| {
            row.age >= options.min_age && row.amount.checked_add(options.delta).is_none()
        });
        if rejected != expected_rejected {
            return Err("encrypted overflow outcome differs from the fixture".into());
        }
        if !rejected {
            for row in &mut expected_rows {
                if row.age >= options.min_age {
                    row.amount += options.delta;
                }
            }
        }
        let timer = Instant::now();
        (table, final_bytes) = write_and_reload(&evaluator, table, &table_path)?;
        let compression_write_reload_ms = elapsed_ms(timer);
        let timer = Instant::now();
        let aggregate =
            owner.decrypt_aggregate_for_experiment(&evaluator.aggregate(&table, &predicate)?)?;
        let query_and_decrypt_ms = elapsed_ms(timer);
        check_aggregate(aggregate, &expected_rows, options.min_age)?;
        cycles.push(Cycle {
            cycle,
            update_ms,
            update_rejected: rejected,
            compression_write_reload_ms,
            query_and_decrypt_ms,
            compressed_table_bytes: final_bytes,
            aggregate: Aggregate {
                count: aggregate.0,
                sum: aggregate.1,
            },
        });
    }

    let logical_plaintext_bytes = options.rows * 3; // u8 age + u16 amount; no Rust struct padding.
    let report = Report {
        experiment: "encrypted age filter, COUNT, SUM, checked UPDATE, disk round trips",
        result_status: "unverified_local_experiment_no_query_proof",
        crate_version: env!("CARGO_PKG_VERSION"),
        tfhe_version: "1.8.1",
        parameters: "PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128 + matching compression",
        os: std::env::consts::OS,
        architecture: std::env::consts::ARCH,
        available_parallelism: std::thread::available_parallelism()?.get(),
        rayon_threads: options.threads,
        rows: options.rows,
        min_age: options.min_age,
        update_delta: options.delta,
        logical_plaintext_bytes,
        evaluation_key_serialized_bytes,
        key_generation_ms,
        encryption_ms,
        initial_compression_write_reload_ms,
        initial_query_and_decrypt_ms,
        initial_compressed_table_bytes: initial_bytes,
        initial_aggregate: Aggregate {
            count: initial.0,
            sum: initial.1,
        },
        cycles,
        compressed_table_to_plaintext_ratio: (logical_plaintext_bytes != 0)
            .then(|| final_bytes as f64 / logical_plaintext_bytes as f64),
        process_peak_resident_bytes: metrics::peak_resident_bytes(),
        total_experiment_ms: elapsed_ms(total),
        artifact_directory: directory.canonicalize()?.to_string_lossy().into_owned(),
    };
    let json = serde_json::to_string_pretty(&report)?;
    fs::write(directory.join("report.json"), &json)?;
    println!("{json}");
    Ok(())
}

fn write_and_reload(
    evaluator: &Evaluator,
    table: EncryptedTable,
    path: &Path,
) -> AppResult<(EncryptedTable, u64)> {
    let bytes = evaluator.compress_table(&table)?;
    drop(table);
    // Only a newly created experiment directory is used; no existing user database is opened.
    fs::write(path, &bytes)?;
    drop(bytes);
    let stored_bytes = fs::metadata(path)?.len();
    let bytes = fs::read(path)?;
    let table = evaluator.restore_trusted_image(&bytes)?;
    Ok((table, stored_bytes))
}

fn fixture(count: usize) -> Vec<PlainRow> {
    let pattern = [
        PlainRow {
            age: 17,
            amount: 10,
        },
        PlainRow {
            age: 18,
            amount: 20,
        },
        PlainRow {
            age: 42,
            amount: 30,
        },
        PlainRow { age: 7, amount: 40 },
    ];
    (0..count)
        .map(|index| pattern[index % pattern.len()])
        .collect()
}

fn check_aggregate(actual: (u32, u32), rows: &[PlainRow], min_age: u8) -> AppResult<()> {
    let selected: Vec<_> = rows.iter().filter(|row| row.age >= min_age).collect();
    let expected = (
        selected.len() as u32,
        selected.iter().map(|row| u32::from(row.amount)).sum(),
    );
    if actual != expected {
        return Err(format!("FHE experiment mismatch: {actual:?}, expected {expected:?}").into());
    }
    Ok(())
}

fn elapsed_ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1_000.0
}

fn create_run_directory(parent: &Path) -> AppResult<PathBuf> {
    fs::create_dir_all(parent)?;
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    for attempt in 0..10 {
        let path = parent.join(format!("run-{stamp}-{}-{attempt}", std::process::id()));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err("could not create a unique experiment directory".into())
}

fn parse_options(arguments: impl IntoIterator<Item = String>) -> AppResult<Option<Options>> {
    let mut options = Options::default();
    let mut arguments = arguments.into_iter();
    while let Some(argument) = arguments.next() {
        if argument == "--help" || argument == "-h" {
            println!(
                "cargo run --release -p fhe-prototype -- [--rows 0..1024] [--cycles 0..100] [--min-age 0..255] [--delta 0..65535] [--threads 1..64] [--output-dir PATH]"
            );
            return Ok(None);
        }
        if !matches!(
            argument.as_str(),
            "--rows" | "--cycles" | "--min-age" | "--delta" | "--threads" | "--output-dir"
        ) {
            return Err(format!("unknown argument: {argument}").into());
        }
        let value = arguments
            .next()
            .ok_or_else(|| format!("missing value for {argument}"))?;
        match argument.as_str() {
            "--rows" => options.rows = value.parse()?,
            "--cycles" => options.cycles = value.parse()?,
            "--min-age" => options.min_age = value.parse()?,
            "--delta" => options.delta = value.parse()?,
            "--threads" => options.threads = value.parse()?,
            "--output-dir" => options.output_dir = PathBuf::from(value),
            _ => unreachable!("validated argument"),
        }
    }
    if options.rows > MAX_ROWS || options.cycles > 100 || !(1..=64).contains(&options.threads) {
        return Err("limits: rows <= 1024, cycles <= 100, threads in 1..=64".into());
    }
    Ok(Some(options))
}
