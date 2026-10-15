#![recursion_limit = "256"]
//! Trusted owner-service broker. It never creates a storage/BFV/PIR Owner.
#[allow(dead_code)]
#[path = "../process_protocol.rs"]
mod process_protocol;
#[allow(dead_code)]
#[path = "../resources.rs"]
mod resources;
use process_protocol::*;
#[path = "../child_memory.rs"]
mod child_memory;
use std::{
    fs::OpenOptions,
    io::{BufRead, BufReader, Read, Write},
    process::{Command, Stdio},
    sync::{Arc, Condvar, Mutex},
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
struct BrokerKey(Zeroizing<[u8; 32]>); // no Debug/serializer/Deref/Clone of secret bytes.
fn native() -> NativeMemory {
    let value = resources::memory_sample();
    NativeMemory {
        working_set_bytes: value.working_set_bytes,
        private_commit_bytes: value.private_commit_bytes,
        native_peak_working_set_bytes: value.native_peak_working_set_bytes,
        native_peak_private_commit_bytes: value.native_peak_private_commit_bytes,
    }
}
enum Receipt {
    Writer(Box<WriterReceipt>),
    Reader(ReaderReceipt),
}
fn line(input: &mut impl BufRead) -> ProtocolResult<Option<Vec<u8>>> {
    let mut out = Vec::new();
    loop {
        let available = input.fill_buf()?;
        if available.is_empty() {
            return if out.is_empty() {
                Ok(None)
            } else {
                Err("Child stdout ended in a partial frame".into())
            };
        }
        let size = available
            .iter()
            .position(|x| *x == b'\n')
            .map_or(available.len(), |n| n + 1);
        if out
            .len()
            .checked_add(size)
            .is_none_or(|n| n > PUBLIC_LINE_BYTES)
        {
            return Err("Child public line exceeds bound".into());
        }
        let complete = available[size - 1] == b'\n';
        out.extend_from_slice(&available[..size]);
        input.consume(size);
        if complete {
            return Ok(Some(out));
        }
    }
}
fn child_program(role: &str) -> ProtocolResult<std::path::PathBuf> {
    let parent = std::env::current_exe()?
        .parent()
        .ok_or("Broker executable parent missing")?
        .to_owned();
    let extension = if cfg!(windows) { ".exe" } else { "" };
    Ok(parent.join(format!("private-bfv-restart-{role}{extension}")))
}
fn spawn(
    role: &'static str,
    config: &Config,
    key: Arc<BrokerKey>,
    start: Option<ReaderStart>,
    results: &mut std::fs::File,
) -> ProtocolResult<Receipt> {
    let seconds = if role == "writer" {
        config.writer_timeout_seconds
    } else {
        config.reader_timeout_seconds
    };
    let mut command = Command::new(child_program(role)?);
    command
        .arg(serde_json::to_string(config)?)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("RAYON_NUM_THREADS", config.threads.to_string());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW; no GUI/visible terminal.
    }
    let mut process = command.spawn()?;
    let pid = process.id();
    let mut stdin = process
        .stdin
        .take()
        .ok_or("Child anonymous stdin missing")?;
    let stdout = process.stdout.take().ok_or("Child stdout missing")?;
    let mut stderr = process.stderr.take().ok_or("Child stderr missing")?;
    let process = Arc::new(Mutex::new(process));
    let complete = Arc::new((Mutex::new(false), Condvar::new()));
    let timer = {
        let process = process.clone();
        let complete = complete.clone();
        thread::spawn(move || {
            let (lock, event) = &*complete;
            let done = lock.lock().expect("Lifecycle lock poisoned");
            let (done, timeout) = event
                .wait_timeout_while(done, Duration::from_secs(seconds), |done| !*done)
                .expect("Lifecycle wait poisoned");
            if timeout.timed_out() && !*done {
                let _ = process.lock().expect("Child lock poisoned").kill();
            }
        })
    };
    let input = thread::spawn(move || -> Result<(), &'static str> {
        stdin
            .write_all(key.0.as_ref())
            .map_err(|_| "Child secret pipe write failed")?;
        if let Some(start) = start {
            write_public_frame(&mut stdin, &start)
                .map_err(|_| "Child public frame write failed")?;
        }
        drop(stdin); // mandatory EOF; no secret key transcript/file/env/argv.
        Ok(())
    });
    let errors = {
        let process = process.clone();
        thread::spawn(move || -> Result<usize, &'static str> {
            // Unknown diagnostics are NEVER copied to a report/console or formatted as Debug.
            let mut buffer = Zeroizing::new([0u8; 1024]);
            let mut count = 0usize;
            loop {
                let read = stderr
                    .read(buffer.as_mut())
                    .map_err(|_| "Child stderr read failed")?;
                if read == 0 {
                    return Ok(count);
                }
                count = count
                    .checked_add(read)
                    .ok_or("Child stderr count overflow")?;
                if count > CHILD_STDERR_BYTES {
                    let _ = process.lock().map_err(|_| "Child lock poisoned")?.kill();
                    return Err("Child stderr bound exceeded");
                }
            }
        })
    };
    let started = Instant::now();
    let observed = (|| -> ProtocolResult<Receipt> {
        let mut reader = BufReader::new(stdout);
        let mut total = 0usize;
        let mut receipt = None;
        while let Some(wire) = line(&mut reader)? {
            total = total
                .checked_add(wire.len())
                .ok_or("Child stdout count overflow")?;
            if total > CHILD_STDOUT_BYTES {
                return Err("Child total stdout exceeds bound".into());
            }
            let value: serde_json::Value = serde_json::from_slice(&wire)?;
            let experiment = value
                .get("experiment")
                .and_then(serde_json::Value::as_str)
                .ok_or("Unframed child public record")?;
            let allowed = match role {
                "writer" => matches!(
                    experiment,
                    "disk-admission"
                        | "disk-table-created"
                        | "restart-writer-update"
                        | "restart-writer-receipt"
                        | "restart-writer-failed"
                ),
                "reader" => matches!(
                    experiment,
                    "disk-admission"
                        | "restart-reader-negative"
                        | "restart-reader-initialized"
                        | "restart-disk-read"
                        | "restart-reader-receipt"
                ),
                _ => false,
            };
            if !allowed {
                return Err("Unexpected child public record kind".into());
            }
            // Only validated PUBLIC record schemas leave the child's pipe. No stderr is persisted.
            serde_json::to_writer(
                &mut *results,
                &serde_json::json!({"role":role,"pid":pid,"record":&value}),
            )?;
            results.write_all(b"\n")?;
            match experiment {
                "restart-writer-receipt" => {
                    if receipt.is_some() {
                        return Err("Duplicate writer receipt".into());
                    }
                    let parsed: WriterReceipt = serde_json::from_value(value)?;
                    parsed.validate(config)?;
                    if parsed.writer_pid != pid {
                        return Err("Writer PID binding mismatch".into());
                    }
                    receipt = Some(Receipt::Writer(Box::new(parsed)));
                }
                "restart-reader-receipt" => {
                    if receipt.is_some() {
                        return Err("Duplicate reader receipt".into());
                    }
                    let parsed: ReaderReceipt = serde_json::from_value(value)?;
                    if parsed.protocol_version != 1
                        || parsed.reader_pid != pid
                        || !parsed.completed
                        || !parsed.correct
                        || parsed.matrix_operations != config.samples * 8 * 32 * config.ids.len()
                        || parsed.reader_key_path != "authenticated-original-secret-import"
                    {
                        return Err("Reader completion binding mismatch".into());
                    }
                    receipt = Some(Receipt::Reader(parsed));
                }
                _ => {}
            }
        }
        receipt.ok_or_else(|| "Child EOF without mandatory completion receipt".into())
    })();
    if observed.is_err() {
        let _ = process.lock().map_err(|_| "Child lock poisoned")?.kill();
    }
    // Never hold a Child mutex during blocking wait: the deadline thread must be able to kill it.
    let status = loop {
        if let Some(status) = process
            .lock()
            .map_err(|_| "Child lock poisoned")?
            .try_wait()?
        {
            break status;
        }
        thread::sleep(Duration::from_millis(5));
    };
    {
        let (lock, event) = &*complete;
        *lock.lock().map_err(|_| "Lifecycle lock poisoned")? = true;
        event.notify_all();
    }
    timer.join().map_err(|_| "Deadline monitor failed")?;
    input
        .join()
        .map_err(|_| "Child stdin task failed")?
        .map_err(|_| "Child stdin protocol failed")?;
    let stderr_bytes = errors
        .join()
        .map_err(|_| "Child diagnostics task failed")?
        .map_err(|_| "Child diagnostics bound failed")?;
    results.flush()?;
    if !status.success() {
        return Err("Child failed or exceeded deadline; reader launch prohibited".into());
    }
    let through_exit = child_memory::sample(&*process.lock().map_err(|_| "Child lock poisoned")?)?;
    let mut receipt = observed?;
    let reported = match &mut receipt {
        Receipt::Writer(value) => &mut value.native,
        Receipt::Reader(value) => &mut value.native,
    };
    if through_exit.native_peak_working_set_bytes < reported.native_peak_working_set_bytes
        || through_exit.native_peak_private_commit_bytes < reported.native_peak_private_commit_bytes
    {
        return Err("Post-exit native peaks lost earlier observed process peaks".into());
    }
    *reported = child_memory::merge(*reported, through_exit);
    write_public_line(
        &serde_json::json!({"experiment":"restart-child-exited","role":role,"pid":pid,
        "exit_code":status.code(),"elapsed_process_ms":started.elapsed().as_secs_f64()*1000.0,
        "stderr_discarded_bytes":stderr_bytes,"parent_native":native(),"eof_observed":true,"child_native_through_exit":through_exit}),
    )?;
    Ok(receipt)
}
fn run() -> ProtocolResult<()> {
    let config = Config::from_args()?;
    if config.directory.exists() {
        return Err("Fresh dataset directory must not already exist".into());
    }
    if !config
        .directory
        .parent()
        .is_some_and(std::path::Path::is_dir)
    {
        return Err("Ignored dataset parent must already exist".into());
    }
    let _monitor = resources::Monitor::start(2_000_000_000);
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(bytes.as_mut()).map_err(|_| "Broker randomness unavailable")?;
    let key = Arc::new(BrokerKey(bytes));
    let report = config.directory.with_extension("broker-results.jsonl");
    let mut results = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&report)?;
    let Receipt::Writer(writer) = spawn("writer", &config, key.clone(), None, &mut results)? else {
        return Err("Wrong child role receipt".into());
    };
    // The successful wait/EOF above is a REAL process-exit barrier. No original Owner memory survives.
    let start = ReaderStart {
        protocol_version: 1,
        writer_exited_successfully: true,
        writer: writer.as_ref().clone(),
    };
    let Receipt::Reader(reader) = spawn("reader", &config, key.clone(), Some(start), &mut results)?
    else {
        return Err("Wrong reader role receipt".into());
    };
    if reader.original_writer_pid != writer.writer_pid {
        return Err("Reader/writer lifecycle binding mismatch".into());
    }
    let broker = native();
    let peak_working_bound = broker
        .native_peak_working_set_bytes
        .checked_add(
            writer
                .native
                .native_peak_working_set_bytes
                .max(reader.native.native_peak_working_set_bytes),
        )
        .ok_or("Aggregate memory bound overflow")?;
    let peak_private_bound = broker
        .native_peak_private_commit_bytes
        .checked_add(
            writer
                .native
                .native_peak_private_commit_bytes
                .max(reader.native.native_peak_private_commit_bytes),
        )
        .ok_or("Aggregate memory bound overflow")?;
    if peak_working_bound >= 2_000_000_000 || peak_private_bound >= 2_000_000_000 {
        return Err("Parent plus active-child conservative native bound exceeds2GB".into());
    }
    write_public_line(
        &serde_json::json!({"experiment":"restart-broker-complete","completed":true,"correct":true,
        "broker_pid":std::process::id(),"writer_pid":writer.writer_pid,"reader_pid":reader.reader_pid,
        "writer_exit_precedes_reader_start":true,"wrapping_key_master_bytes":32,"wrapping_key_persisted":false,
        "parent_native":broker,"writer_native":writer.native,"reader_native":reader.native,
        "sum_of_reported_native_peaks_working_bound":peak_working_bound,
        "sum_of_reported_native_peaks_private_bound":peak_private_bound,
        "memory_bound_is_conservative_not_simultaneous_measurement":true,"child_os_native_peaks_observed_after_exit":true,"broker_result_artifact_bytes":results.metadata()?.len(),
        "reader_file_ledger":reader.file_ledger,"reader_restore":reader.restore,
        "result_artifact":report,"full_machine_restart":false,"key_custody_external":true,
        "durable_fsync":false,"rollback_authority_external":true,"computation_proof":false}),
    )?;
    drop(key);
    Ok(())
}
fn main() {
    if run().is_err() {
        eprintln!("restart broker failed; private diagnostics are not formatted or persisted");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_lines_require_newline_eof_and_a_fixed_preallocation_bound() {
        assert!(line(&mut &b"{}"[..]).is_err());
        assert!(line(&mut &vec![b'x'; PUBLIC_LINE_BYTES + 1][..]).is_err());
        let mut input = &b"{}\n"[..];
        assert_eq!(line(&mut input).unwrap(), Some(b"{}\n".to_vec()));
        assert!(line(&mut input).unwrap().is_none());
    }
}
