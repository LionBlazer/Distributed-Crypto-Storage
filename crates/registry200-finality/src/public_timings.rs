//! Fixed, bounded observation only. No proof, candidate or consensus authority.
//! Sections only accumulate numbers; the actor flushes after releasing its permit.
use std::{
    cell::RefCell,
    io::{self, Write},
    sync::{
        OnceLock,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Instant,
};

const PENDING: usize = 16;
const MAX_LINES: usize = 4096;
static ENABLED: OnceLock<bool> = OnceLock::new();
static ORDINAL: AtomicU64 = AtomicU64::new(0);
static LINES: AtomicUsize = AtomicUsize::new(0);

pub(crate) fn enabled() -> bool {
    *ENABLED.get_or_init(|| {
        std::env::var_os("DCS_PUBLIC_TIMINGS").as_deref() == Some(std::ffi::OsStr::new("1"))
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Import,
    Propose,
    Proposal,
    Vote,
    Certificate,
    Timeout,
    Checkpoint,
}
impl Kind {
    fn label(self) -> &'static str {
        match self {
            Self::Import => "import",
            Self::Propose => "propose",
            Self::Proposal => "proposal",
            Self::Vote => "vote",
            Self::Certificate => "certificate",
            Self::Timeout => "timeout",
            Self::Checkpoint => "checkpoint",
        }
    }
}
#[derive(Clone, Copy)]
pub(crate) enum Stage {
    Application,
    HandleWal,
    StateWait,
    Preflight,
    FloorAppend,
    Install,
    Advance,
    Synchronize,
    ImportPrepare,
    ImportCharge,
    ImportCommit,
}
const STAGES: usize = Stage::ImportCommit as usize + 1;
#[derive(Clone, Copy)]
struct Metric {
    calls: u64,
    micros: u64,
}
const EMPTY: Metric = Metric {
    calls: 0,
    micros: 0,
};
struct Active {
    ordinal: u64,
    slot: u64,
    kind: Kind,
    start: Instant,
    metrics: [Metric; STAGES],
}
#[derive(Clone, Copy)]
struct Report {
    ordinal: u64,
    slot: u64,
    kind: Kind,
    total_us: u64,
    metrics: [Metric; STAGES],
}
struct Buffer {
    active: Option<Active>,
    finished: [Option<Report>; PENDING],
    len: usize,
}
impl Buffer {
    const fn new() -> Self {
        Self {
            active: None,
            finished: [None; PENDING],
            len: 0,
        }
    }
}
thread_local! {
    static BUFFER: RefCell<Buffer> = const { RefCell::new(Buffer::new()) };
}
fn micros(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX)
}
pub(crate) struct Scope {
    ordinal: Option<u64>,
}
impl Scope {
    pub(crate) fn new(progress: bool, kind: Kind, slot: u64) -> Self {
        if !progress || !enabled() {
            return Self { ordinal: None };
        }
        Self::begin(kind, slot)
    }
    fn begin(kind: Kind, slot: u64) -> Self {
        let ordinal = BUFFER
            .try_with(|cell| {
                let Ok(mut buffer) = cell.try_borrow_mut() else {
                    return None;
                };
                if buffer.active.is_some() {
                    return None;
                }
                let ordinal = ORDINAL
                    .try_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
                        old.checked_add(1)
                    })
                    .ok()?
                    .checked_add(1)?;
                buffer.active = Some(Active {
                    ordinal,
                    slot,
                    kind,
                    start: Instant::now(),
                    metrics: [EMPTY; STAGES],
                });
                Some(ordinal)
            })
            .ok()
            .flatten();
        Self { ordinal }
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        let Some(ordinal) = self.ordinal else {
            return;
        };
        let _ = BUFFER.try_with(|cell| {
            let Ok(mut buffer) = cell.try_borrow_mut() else {
                return;
            };
            if buffer
                .active
                .as_ref()
                .is_none_or(|active| active.ordinal != ordinal)
            {
                return;
            }
            let Some(active) = buffer.active.take() else {
                return;
            };
            let report = Report {
                ordinal,
                slot: active.slot,
                kind: active.kind,
                total_us: micros(active.start),
                metrics: active.metrics,
            };
            if buffer.len < PENDING {
                let index = buffer.len;
                buffer.finished[index] = Some(report);
                buffer.len += 1;
            }
        });
    }
}
pub(crate) struct Section {
    stage: Stage,
    start: Option<Instant>,
    ordinal: Option<u64>,
}
impl Section {
    pub(crate) fn new(stage: Stage) -> Self {
        if !enabled() {
            return Self {
                stage,
                start: None,
                ordinal: None,
            };
        }
        let ordinal = BUFFER
            .try_with(|cell| {
                cell.try_borrow()
                    .ok()
                    .and_then(|buffer| buffer.active.as_ref().map(|active| active.ordinal))
            })
            .ok()
            .flatten();
        Self {
            stage,
            start: ordinal.map(|_| Instant::now()),
            ordinal,
        }
    }
}
impl Drop for Section {
    fn drop(&mut self) {
        let (Some(start), Some(ordinal)) = (self.start, self.ordinal) else {
            return;
        };
        let elapsed = micros(start);
        let _ = BUFFER.try_with(|cell| {
            let Ok(mut buffer) = cell.try_borrow_mut() else {
                return;
            };
            let Some(active) = buffer.active.as_mut() else {
                return;
            };
            if active.ordinal != ordinal {
                return;
            }
            let metric = &mut active.metrics[self.stage as usize];
            metric.calls = metric.calls.saturating_add(1);
            metric.micros = metric.micros.saturating_add(elapsed);
        });
    }
}
fn drain() -> Option<[Option<Report>; PENDING]> {
    BUFFER
        .try_with(|cell| {
            let Ok(mut buffer) = cell.try_borrow_mut() else {
                return None;
            };
            if buffer.len == 0 {
                return None;
            }
            buffer.len = 0;
            Some(std::mem::replace(&mut buffer.finished, [None; PENDING]))
        })
        .ok()
        .flatten()
}
fn reserve_line(counter: &AtomicUsize) -> bool {
    counter
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
            if old < MAX_LINES { Some(old + 1) } else { None }
        })
        .is_ok()
}
fn write_report(writer: &mut impl Write, report: Report) -> io::Result<()> {
    let m = report.metrics;
    let line = format!(
        "dcs_public_timing component=progress_finality pid={} ordinal={} kind={} slot={} total_us={} app_calls={} app_us={} handle_wal_us={} state_wait_us={} floor_preflight_us={} floor_append_sync_us={} floor_install_us={} voter_advance_us={} synchronize_us={} import_prepare_us={} import_charge_us={} import_commit_us={}\n",
        std::process::id(),
        report.ordinal,
        report.kind.label(),
        report.slot,
        report.total_us,
        m[Stage::Application as usize].calls,
        m[Stage::Application as usize].micros,
        m[Stage::HandleWal as usize].micros,
        m[Stage::StateWait as usize].micros,
        m[Stage::Preflight as usize].micros,
        m[Stage::FloorAppend as usize].micros,
        m[Stage::Install as usize].micros,
        m[Stage::Advance as usize].micros,
        m[Stage::Synchronize as usize].micros,
        m[Stage::ImportPrepare as usize].micros,
        m[Stage::ImportCharge as usize].micros,
        m[Stage::ImportCommit as usize].micros
    );
    if line.len() >= 1024 {
        return Ok(());
    }
    writer.write_all(line.as_bytes())
}
fn emit(writer: &mut impl Write, report: Report) {
    let _ = write_report(writer, report);
}

/// Emits already-finished, bounded Progress observation records when
/// DCS_PUBLIC_TIMINGS=1 was set before first use. Call after releasing protocol
/// locks and the proof permit. It returns no value and grants no authority.
///
/// Records contain fixed public tags, the actual PID and numeric ordinals/slots/durations.
/// At most 16 records wait per thread and 4096 lines emit per process. Additional
/// diagnostics may be dropped. Disabled calls use no clock, TLS or diagnostic IO.
/// Output errors are ignored and cannot change a protocol result. Intervals
/// overlap: handle/WAL includes application work; floor append includes its sync.
/// Neither a duration nor app_calls is a proof, fsync-only cost or FHE CPU time.
pub fn flush_public_timings() {
    if !enabled() {
        return;
    }
    let Some(reports) = drain() else {
        return;
    };
    if LINES.load(Ordering::Relaxed) >= MAX_LINES {
        return;
    }
    let mut writer = io::stderr().lock();
    for report in reports.into_iter().flatten() {
        if !reserve_line(&LINES) {
            break;
        }
        emit(&mut writer, report);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn report() -> Report {
        Report {
            ordinal: 7,
            slot: 4,
            kind: Kind::Import,
            total_us: 12,
            metrics: [EMPTY; STAGES],
        }
    }
    #[test]
    fn formatted_observation_has_one_fixed_public_record() {
        let mut bytes = Vec::new();
        write_report(&mut bytes, report()).unwrap();
        let line = String::from_utf8(bytes).unwrap();
        assert_eq!(line.lines().count(), 1);
        assert!(line.starts_with(&format!("dcs_public_timing component=progress_finality pid={} ordinal=7 kind=import slot=4 total_us=12 app_calls=0 app_us=0 ", std::process::id())));
        assert!(line.ends_with("import_commit_us=0\n"));
        assert!(line.len() < 1024);
        let mut largest = report();
        largest.ordinal = u64::MAX;
        largest.slot = u64::MAX;
        largest.kind = Kind::Checkpoint;
        largest.total_us = u64::MAX;
        largest.metrics = [Metric {
            calls: u64::MAX,
            micros: u64::MAX,
        }; STAGES];
        let mut bytes = Vec::new();
        write_report(&mut bytes, largest).unwrap();
        assert!(
            bytes.len() < 1024,
            "fixed grammar stays bounded at maximum integers"
        );
    }
    #[test]
    fn failed_diagnostic_output_has_no_error_return() {
        struct Broken(usize);
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                self.0 += 1;
                Err(io::Error::other("diagnostic-only write failure"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut writer = Broken(0);
        emit(&mut writer, report());
        assert!(writer.0 > 0);
    }
    #[test]
    fn output_budget_never_reserves_a_line_beyond_the_fixed_limit() {
        let counter = AtomicUsize::new(0);
        for _ in 0..MAX_LINES {
            assert!(reserve_line(&counter));
        }
        assert!(!reserve_line(&counter));
        assert!(!reserve_line(&counter));
        assert_eq!(counter.load(Ordering::Relaxed), MAX_LINES);
    }
    #[test]
    fn nested_observation_does_not_replace_the_original_scope() {
        let outer = Scope::begin(Kind::Import, 11);
        let inner = Scope::begin(Kind::Checkpoint, 12);
        assert!(outer.ordinal.is_some());
        assert!(inner.ordinal.is_none());
        drop(inner);
        drop(outer);
        let reports = drain().unwrap();
        let mut reports = reports.into_iter().flatten();
        let report = reports.next().unwrap();
        assert_eq!(report.slot, 11);
        assert_eq!(report.kind, Kind::Import);
        assert!(reports.next().is_none());
    }
}
