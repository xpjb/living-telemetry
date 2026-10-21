use std::collections::{HashSet, VecDeque};
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::platform;
use crate::protocol::{
    Field, FrameSummary, Record, Report, ReportRequest, RunCheckpoint, SCHEMA_VERSION, Snapshot,
    WatchMessage, WatchdogLaunch, unique_id, unix_ms,
};
use crate::spool::{Spool, atomic_json};

const WATCHDOG_ARG: &str = "--living-telemetry-watchdog";
const WATCHDOG_CONFIG: &str = "LIVING_TELEMETRY_WATCHDOG_CONFIG";
const SNAPSHOT_FRESH_MS: u64 = 3_000;
const INCIDENT_CONTEXT_RECORDS: usize = 128;
const CHECKPOINT_RECORDS: usize = 256;
const SENT_RECORD_CACHE: usize = 8_192;
const ACTIVE_CHECKPOINT_MS: u64 = 15_000;

struct DumpBudget {
    limit: u32,
    cooldown_ms: u64,
    attempts: u32,
    suppressed: u64,
    last_attempt_ms: Option<u64>,
}
impl DumpBudget {
    fn reserve(&mut self, now: u64) -> &'static str {
        let reason = if self.attempts >= self.limit { "session_limit" }
            else if self.last_attempt_ms.is_some_and(|last| now.saturating_sub(last) < self.cooldown_ms) { "cooldown" }
            else {
                // Reserve BEFORE capture: failed dumps must not become a retry storm.
                self.attempts += 1;
                self.last_attempt_ms = Some(now);
                return "capture";
            };
        self.suppressed += 1;
        reason
    }
}

pub(crate) fn spawn(launch: &WatchdogLaunch) -> Result<(Child, Option<ChildStdin>), String> {
    let executable = std::env::current_exe().map_err(|err| err.to_string())?;
    let config = serde_json::to_string(launch).map_err(|err| err.to_string())?;
    let mut command = Command::new(executable);
    command
        .arg(WATCHDOG_ARG)
        .env(WATCHDOG_CONFIG, config)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW);
    }
    let mut child = command
        .spawn()
        .map_err(|err| format!("spawn telemetry watchdog: {err}"))?;
    let stdin = child.stdin.take();
    Ok((child, stdin))
}

pub fn run_from_args() -> bool {
    if std::env::args_os().nth(1).as_deref() != Some(std::ffi::OsStr::new(WATCHDOG_ARG)) {
        return false;
    }
    let result = std::env::var(WATCHDOG_CONFIG)
        .map_err(|err| err.to_string())
        .and_then(|value| {
            serde_json::from_str::<WatchdogLaunch>(&value).map_err(|err| err.to_string())
        })
        .and_then(run_sidecar);
    if let Err(err) = result {
        let _ = fs::write(
            std::env::temp_dir().join("living-telemetry-watchdog-error.log"),
            err,
        );
    }
    true
}

fn run_sidecar(launch: WatchdogLaunch) -> Result<(), String> {
    let (sender, receiver) = mpsc::channel();
    thread::Builder::new()
        .name("living-telemetry-watchdog-input".to_string())
        .spawn(move || {
            for line in BufReader::new(std::io::stdin().lock()).lines() {
                let Ok(line) = line else {
                    break;
                };
                let Ok(message) = serde_json::from_str::<WatchMessage>(&line) else {
                    continue;
                };
                if sender.send(message).is_err() {
                    break;
                }
            }
        })
        .map_err(|err| err.to_string())?;

    let mut runtime = Runtime::new(launch);
    loop {
        let timeout = if runtime.snapshot.busy.is_some() {
            Duration::from_millis(50)
        } else {
            Duration::from_secs(1)
        };
        match receiver.recv_timeout(timeout) {
            Ok(WatchMessage::Snapshot(snapshot)) => runtime.accept_snapshot(snapshot),
            Ok(WatchMessage::Report(report)) => runtime.report(report),
            Ok(WatchMessage::Clean { .. }) => {
                runtime.clean(true);
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => runtime.tick(),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                thread::sleep(Duration::from_millis(150));
                runtime.unclean_exit();
                break;
            }
        }
    }
    Ok(())
}

struct Incident {
    episode: u64,
    busy_since_ms: u64,
    stall_reported: bool,
    hang_reported: bool,
    ten_second_reported: bool,
    last_continuation_ms: u64,
}

pub(crate) struct Runtime {
    launch: WatchdogLaunch,
    spool: Option<Spool>,
    snapshot: Snapshot,
    records: VecDeque<Record>,
    performance: Vec<Record>,
    incident: Option<Incident>,
    last_performance_ms: u64,
    last_summary_ms: u64,
    last_summary_frames: u64,
    last_checkpoint_ms: u64,
    flush_sender: Option<mpsc::SyncSender<()>>,
    uploader: Option<thread::JoinHandle<()>>,
    checkpoint_path: PathBuf,
    cleaned: bool,
    dump_budget: DumpBudget,
    sent_records: HashSet<u64>,
    sent_order: VecDeque<u64>,
}

impl Runtime {
    pub fn new(launch: WatchdogLaunch) -> Self {
        let spool = Spool::new(
            launch.data_dir.join("spool"),
            launch.spool_max_bytes,
            launch.endpoint.as_deref(),
        )
        .ok();
        let (flush_sender, uploader) = spool
            .as_ref()
            .and_then(|spool| {
                recover_stale_runs(&launch, spool);
                let uploader = Spool::new(
                    launch.data_dir.join("spool"),
                    launch.spool_max_bytes,
                    launch.endpoint.as_deref(),
                )
                .ok()?;
                let (sender, receiver) = mpsc::sync_channel(1);
                let handle = thread::Builder::new()
                    .name("living-telemetry-uploader".to_string())
                    .spawn(move || {
                        loop {
                            match receiver.recv_timeout(Duration::from_secs(30)) {
                                Ok(()) | Err(mpsc::RecvTimeoutError::Timeout) => uploader.flush(),
                                Err(mpsc::RecvTimeoutError::Disconnected) => {
                                    uploader.flush();
                                    break;
                                }
                            }
                        }
                    })
                    .ok()?;
                Some((sender, handle))
            })
            .map_or((None, None), |(sender, handle)| {
                (Some(sender), Some(handle))
            });
        if let Some(sender) = &flush_sender {
            let _ = sender.try_send(());
        }
        let checkpoint_path = launch
            .data_dir
            .join("runs")
            .join(format!("{}.json", launch.run_id));
        let dump_budget = DumpBudget { limit: launch.hang_dump_limit,
            cooldown_ms: launch.hang_dump_cooldown_ms, attempts: 0, suppressed: 0, last_attempt_ms: None };
        Self {
            snapshot: Snapshot {
                unix_ms: launch.start_unix_ms,
                uptime_ms: 0,
                frame_budget_us: 16_667,
                busy: None,
                state: Vec::new(),
                records: Vec::new(),
                frame_summary: FrameSummary::default(),
                recorder_dropped: 0,
            },
            records: VecDeque::with_capacity(launch.ring_capacity.min(4_096)),
            performance: Vec::new(),
            incident: None,
            last_performance_ms: launch.start_unix_ms,
            last_summary_ms: launch.start_unix_ms,
            last_summary_frames: 0,
            last_checkpoint_ms: 0,
            flush_sender,
            uploader,
            checkpoint_path,
            cleaned: false,
            dump_budget,
            sent_records: HashSet::new(),
            sent_order: VecDeque::new(),
            spool,
            launch,
        }
    }

    pub fn accept_snapshot(&mut self, mut snapshot: Snapshot) {
        let new_records = std::mem::take(&mut snapshot.records);
        let frame_budget_us = snapshot.frame_budget_us.max(1);
        for record in new_records {
            if self.records.len() == self.launch.ring_capacity {
                self.records.pop_front();
            }
            if matches!(record, Record::Frame(_)) || is_slow_interval(&record, frame_budget_us) {
                self.performance.push(record.clone());
            }
            self.records.push_back(record);
        }
        if snapshot.busy.is_none() {
            self.report_recovery(snapshot.unix_ms);
        } else if self.incident.as_ref().is_some_and(|incident| {
            Some(incident.episode) != snapshot.busy.as_ref().map(|busy| busy.episode)
        }) {
            self.report_recovery(snapshot.unix_ms);
        }
        self.snapshot = snapshot;
        if self.performance.len() >= 1_024 {
            self.report_performance();
        }
        self.tick();
    }

    pub fn report(&mut self, report: ReportRequest) {
        let records = self.records.iter().cloned().collect();
        self.emit(
            &report.topic,
            &report.kind,
            report.fields,
            Vec::new(),
            records,
        );
    }

    pub fn tick(&mut self) {
        let now = unix_ms();
        self.check_stall(now);
        if now.saturating_sub(self.last_performance_ms) >= 10_000 && !self.performance.is_empty() {
            self.report_performance();
        }
        if now.saturating_sub(self.last_summary_ms) >= 60_000
            && self.snapshot.frame_summary.frames != self.last_summary_frames
        {
            self.emit(
                "performance",
                "runtime_summary",
                Vec::new(),
                Vec::new(),
                Vec::new(),
            );
            self.last_summary_ms = now;
            self.last_summary_frames = self.snapshot.frame_summary.frames;
        }
        let checkpoint_interval_ms = if self.snapshot.busy.is_some() {
            ACTIVE_CHECKPOINT_MS
        } else {
            30_000
        };
        if now.saturating_sub(self.last_checkpoint_ms) >= checkpoint_interval_ms {
            self.write_checkpoint();
            self.last_checkpoint_ms = now;
        }
    }

    pub fn clean(&mut self, wait_for_upload: bool) {
        if self.cleaned {
            return;
        }
        self.cleaned = true;
        if !self.performance.is_empty() {
            self.report_performance();
        }
        let _ = fs::remove_file(&self.checkpoint_path);
        self.flush_sender.take();
        if wait_for_upload {
            if let Some(uploader) = self.uploader.take() {
                let _ = uploader.join();
            }
        } else {
            self.uploader.take();
        }
    }

    pub fn unclean_exit(&mut self) {
        if self.cleaned {
            return;
        }
        self.cleaned = true;
        let alive = platform::process_alive(self.launch.parent_pid, self.launch.parent_start_token);
        let dump = self
            .launch
            .native_dump_path
            .exists()
            .then(|| self.launch.native_dump_path.clone());
        let kind = if dump.is_some() {
            "native_crash"
        } else if alive {
            "watchdog_channel_closed"
        } else {
            "process_exit"
        };
        let mut fields = vec![Field::new("parent_alive", alive)];
        if let Some(exit_code) = platform::process_sample(self.launch.parent_pid).exit_code {
            fields.push(Field::new("exit_code", exit_code));
        }
        self.emit(
            "crash",
            kind,
            fields,
            dump.into_iter().collect(),
            self.records.iter().cloned().collect(),
        );
        self.flush_sender.take();
        if let Some(uploader) = self.uploader.take() {
            let _ = uploader.join();
        }
        let _ = fs::remove_file(&self.checkpoint_path);
    }

    fn check_stall(&mut self, now: u64) {
        if now.saturating_sub(self.snapshot.unix_ms) > SNAPSHOT_FRESH_MS {
            return;
        }
        let Some(busy) = self.snapshot.busy.clone() else {
            return;
        };
        if self
            .incident
            .as_ref()
            .is_none_or(|incident| incident.episode != busy.episode)
        {
            self.incident = Some(Incident {
                episode: busy.episode,
                busy_since_ms: busy.since_unix_ms,
                stall_reported: false,
                hang_reported: false,
                ten_second_reported: false,
                last_continuation_ms: now,
            });
        }
        // A queued snapshot is evidence only up to its own sampling time.
        // Counting IPC/spool delay as UI time creates false hangs (and costly
        // Windows dumps) for callbacks which have already finished.
        let stale_ms = self
            .snapshot
            .unix_ms
            .saturating_sub(busy.last_progress_unix_ms);
        let stall_ms = self.launch.stall_ms;
        let hang_ms = self.launch.hang_ms.max(stall_ms);
        let mut emit_stall = false;
        let mut emit_hang = false;
        let mut emit_continuation = false;
        if let Some(incident) = self.incident.as_mut() {
            if stale_ms >= stall_ms && !incident.stall_reported {
                incident.stall_reported = true;
                emit_stall = true;
            }
            if stale_ms >= hang_ms && !incident.hang_reported {
                incident.hang_reported = true;
                emit_hang = true;
            }
            if stale_ms >= 10_000 && !incident.ten_second_reported {
                incident.ten_second_reported = true;
                incident.last_continuation_ms = now;
                emit_continuation = true;
            } else if stale_ms >= 60_000
                && now.saturating_sub(incident.last_continuation_ms) >= 60_000
            {
                incident.last_continuation_ms = now;
                emit_continuation = true;
            }
        }
        let sampled_at = self.snapshot.unix_ms;
        let common = || {
            vec![
                Field::new("episode", busy.episode),
                Field::new("activity", busy.activity.clone()),
                Field::new("stale_ms", stale_ms),
                Field::new("busy_ms", sampled_at.saturating_sub(busy.since_unix_ms)),
                Field::new("watchdog_lag_ms", now.saturating_sub(sampled_at)),
            ]
        };
        if emit_stall {
            self.emit(
                "hang",
                "stall",
                common(),
                Vec::new(),
                self.incident_records(),
            );
        }
        if emit_hang {
            let dump = self
                .launch
                .data_dir
                .join("attachments")
                .join(format!("{}-hang-{}.dmp", self.launch.run_id, busy.episode));
            let decision = self.dump_budget.reserve(now);
            let mut fields = common();
            let mut attachments = Vec::new();
            let status = if decision == "capture" {
                let started = Instant::now();
                let result = platform::write_minidump(self.launch.parent_pid, &dump);
                fields.push(Field::new("dump_capture_us", started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64));
                if result.is_ok() { attachments.push(dump); "captured" } else { "failed" }
            } else { decision };
            fields.push(Field::new("dump_status", status));
            self.emit(
                "hang",
                "hang",
                fields,
                attachments,
                self.incident_records(),
            );
        }
        if emit_continuation {
            self.emit(
                "hang",
                "hang_continues",
                common(),
                Vec::new(),
                self.incident_records(),
            );
        }
    }

    fn report_recovery(&mut self, now: u64) {
        let Some(incident) = self.incident.take() else {
            return;
        };
        if !incident.stall_reported {
            return;
        }
        self.emit(
            "hang",
            "stall_recovered",
            vec![
                Field::new("episode", incident.episode),
                Field::new("blocked_ms", now.saturating_sub(incident.busy_since_ms)),
                Field::new("reached_hang", incident.hang_reported),
            ],
            Vec::new(),
            self.incident_records(),
        );
    }

    fn report_performance(&mut self) {
        if self.performance.is_empty() {
            return;
        }
        let targets = std::mem::take(&mut self.performance);
        let dropped = targets
            .iter()
            .filter(|record| matches!(record, Record::Frame(_)))
            .count();
        let operations = targets.len().saturating_sub(dropped);
        let start_us = targets
            .iter()
            .map(Record::uptime_us)
            .min()
            .unwrap_or(0)
            .saturating_sub(50_000);
        let end_us = targets
            .iter()
            .map(|record| record.uptime_us().saturating_add(record.duration_us()))
            .max()
            .unwrap_or(start_us)
            .saturating_add(50_000);
        let mut seen: HashSet<_> = targets.iter().map(Record::seq).collect();
        let context = self.records.iter().rev()
            .filter(|record| (start_us..=end_us).contains(&record.uptime_us()))
            .filter(|record| seen.insert(record.seq()))
            .take(INCIDENT_CONTEXT_RECORDS).cloned().collect::<Vec<_>>();
        let mut records = targets;
        records.extend(context);
        records.sort_by_key(Record::seq);
        self.emit(
            "performance",
            "slow_intervals",
            vec![
                Field::new("frame_drops", dropped),
                Field::new("slow_operations", operations),
            ],
            Vec::new(),
            records,
        );
        self.last_performance_ms = unix_ms();
    }

    fn emit(
        &mut self,
        topic: &str,
        kind: &str,
        mut fields: Vec<Field>,
        attachments: Vec<PathBuf>,
        records: Vec<Record>,
    ) {
        let automatic = matches!(topic, "performance" | "hang");
        let delta = automatic && kind != "stall";
        let records: Vec<_> = records.into_iter()
            .filter(|record| !delta || !self.sent_records.contains(&record.seq())).collect();
        let sequences = automatic.then(|| records.iter().map(Record::seq).collect::<Vec<_>>());
        if automatic {
            fields.push(Field::new("records_scope", if delta { "session_delta" } else { "incident_context" }));
            fields.extend([
                Field::new("automatic_dump_attempts", self.dump_budget.attempts),
                Field::new("automatic_dump_suppressed", self.dump_budget.suppressed),
            ]);
        }
        let process = platform::process_sample(self.launch.parent_pid);
        let report = Report {
            schema: SCHEMA_VERSION,
            report_id: unique_id(kind),
            topic: topic.to_string(),
            kind: kind.to_string(),
            app: self.launch.app.clone(),
            version: self.launch.version.clone(),
            device: self.launch.device.clone(),
            run_id: self.launch.run_id.clone(),
            pid: self.launch.parent_pid,
            unix_ms: unix_ms(),
            uptime_ms: self.snapshot.uptime_ms,
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            process: Some(process),
            state: self.snapshot.state.clone(),
            frame_summary: self.snapshot.frame_summary.clone(),
            recorder_dropped: self.snapshot.recorder_dropped,
            records,
            fields,
            attachments: Vec::new(),
        };
        let queued = self.spool.as_ref().is_some_and(|spool| spool.enqueue(report, attachments).is_ok());
        if queued {
            if let Some(sequences) = sequences {
                for seq in sequences {
                    if self.sent_records.insert(seq) { self.sent_order.push_back(seq); }
                }
                while self.sent_order.len() > SENT_RECORD_CACHE {
                    if let Some(seq) = self.sent_order.pop_front() { self.sent_records.remove(&seq); }
                }
            }
            if let Some(sender) = &self.flush_sender { let _ = sender.try_send(()); }
        }
    }

    fn incident_records(&self) -> Vec<Record> {
        self.records.iter().rev().take(INCIDENT_CONTEXT_RECORDS).rev().cloned().collect()
    }

    fn write_checkpoint(&self) {
        let checkpoint = RunCheckpoint {
            launch: self.launch.clone(),
            snapshot: self.snapshot.clone(),
            records: self.records.iter().rev().take(CHECKPOINT_RECORDS).rev().cloned().collect(),
        };
        let _ = atomic_json(&self.checkpoint_path, &checkpoint);
    }
}

fn recover_stale_runs(launch: &WatchdogLaunch, spool: &Spool) {
    let runs = launch.data_dir.join("runs");
    let Ok(entries) = fs::read_dir(&runs) else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if path.extension().is_none_or(|extension| extension != "json") {
            continue;
        }
        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        let Ok(checkpoint) = serde_json::from_slice::<RunCheckpoint>(&bytes) else {
            continue;
        };
        if checkpoint.launch.run_id == launch.run_id
            || platform::process_alive(
                checkpoint.launch.parent_pid,
                checkpoint.launch.parent_start_token,
            )
        {
            continue;
        }
        let dump = checkpoint
            .launch
            .native_dump_path
            .exists()
            .then(|| checkpoint.launch.native_dump_path.clone());
        let report = Report {
            schema: SCHEMA_VERSION,
            report_id: unique_id("previous-unclean"),
            topic: "crash".to_string(),
            kind: "previous_unclean_exit".to_string(),
            app: checkpoint.launch.app,
            version: checkpoint.launch.version,
            device: checkpoint.launch.device,
            run_id: checkpoint.launch.run_id,
            pid: checkpoint.launch.parent_pid,
            unix_ms: unix_ms(),
            uptime_ms: checkpoint.snapshot.uptime_ms,
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            process: Some(platform::process_sample(checkpoint.launch.parent_pid)),
            state: checkpoint.snapshot.state,
            frame_summary: checkpoint.snapshot.frame_summary,
            recorder_dropped: checkpoint.snapshot.recorder_dropped,
            records: checkpoint.records,
            fields: vec![Field::new(
                "checkpoint_unix_ms",
                checkpoint.snapshot.unix_ms,
            )],
            attachments: Vec::new(),
        };
        let _ = spool.enqueue(report, dump.into_iter().collect());
        let _ = fs::remove_file(path);
    }
}

fn is_slow_interval(record: &Record, frame_budget_us: u64) -> bool {
    matches!(
        record,
        Record::Event(event)
            if event.name == "callback_over_budget"
                || event.duration_us.is_some_and(|duration| duration > frame_budget_us)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{BusyState, FrameRecord, Phase, ReportRequest, SpoolEnvelope};

    fn launch(root: PathBuf) -> WatchdogLaunch {
        WatchdogLaunch {
            app: "test".to_string(),
            version: "1".to_string(),
            device: "device".to_string(),
            run_id: unique_id("run"),
            parent_pid: std::process::id(),
            parent_start_token: platform::process_sample(std::process::id()).start_token,
            start_unix_ms: unix_ms(),
            data_dir: root,
            endpoint: None,
            native_dump_path: PathBuf::new(),
            ring_capacity: 64,
            spool_max_bytes: 4 * 1024 * 1024,
            stall_ms: 250,
            hang_ms: 2_000,
            hang_dump_limit: crate::protocol::default_hang_dump_limit(),
            hang_dump_cooldown_ms: crate::protocol::default_hang_dump_cooldown_ms(),
        }
    }

    fn test_record(seq: u64) -> Record {
        Record::Event(crate::protocol::EventRecord {
            seq, uptime_us: seq * 1_000, unix_ms: unix_ms(), thread: "ui".into(),
            category: "test".into(), name: "work".into(), duration_us: Some(20_000), fields: Vec::new(),
        })
    }

    fn reports(root: &std::path::Path) -> Vec<SpoolEnvelope> {
        fs::read_dir(root.join("spool")).unwrap().filter_map(Result::ok)
            .filter_map(|entry| fs::read(entry.path()).ok())
            .filter_map(|bytes| serde_json::from_slice(&bytes).ok()).collect()
    }

    #[test]
    fn automatic_dump_budget_has_cooldown_and_session_limit_even_after_failure() {
        let mut budget = DumpBudget { limit: 2, cooldown_ms: 600_000,
            attempts: 0, suppressed: 0, last_attempt_ms: None };
        assert_eq!(budget.reserve(1_000), "capture");
        // A reserved attempt is consumed even if the OS capture fails.
        assert_eq!(budget.reserve(1_001), "cooldown");
        assert_eq!(budget.reserve(600_999), "cooldown");
        assert_eq!(budget.reserve(601_000), "capture");
        assert_eq!(budget.reserve(1_500_000), "session_limit");
        assert_eq!((budget.attempts, budget.suppressed), (2, 3));
        budget.limit = 0;
        assert_eq!(budget.reserve(9_000_000), "session_limit");
    }

    #[test]
    fn automatic_reports_send_record_deltas_but_repro_and_crash_keep_full_context() {
        let root = std::env::temp_dir().join(unique_id("living-telemetry-deltas"));
        let mut runtime = Runtime::new(launch(root.clone()));
        runtime.records = (1..=1_000).map(test_record).collect();
        runtime.emit("hang", "stall", Vec::new(), Vec::new(), runtime.incident_records());
        runtime.performance = runtime.records.iter().cloned().collect();
        runtime.report_performance();
        runtime.emit("hang", "hang_continues", Vec::new(), Vec::new(), runtime.incident_records());
        runtime.report(ReportRequest { topic: "feedback".into(), kind: "repro".into(), fields: Vec::new() });
        runtime.emit("crash", "panic", Vec::new(), Vec::new(), runtime.records.iter().cloned().collect());
        let all = reports(&root);
        let find = |kind: &str| &all.iter().find(|e| e.report.kind == kind).unwrap().report;
        assert_eq!(find("stall").records.len(), INCIDENT_CONTEXT_RECORDS);
        assert_eq!(find("slow_intervals").records.len(), 1_000 - INCIDENT_CONTEXT_RECORDS);
        assert!(find("hang_continues").records.is_empty());
        assert_eq!(find("repro").records.len(), 1_000);
        assert_eq!(find("panic").records.len(), 1_000);
        let sent = find("stall").records.iter().chain(&find("slow_intervals").records)
            .map(Record::seq).collect::<HashSet<_>>();
        assert_eq!(sent.len(), 1_000, "no exact slow target may disappear during deduplication");
        let bytes = |kind| serde_json::to_vec(find(kind)).unwrap().len();
        assert!(bytes("hang_continues") < bytes("stall") / 4);
        println!("bounded incident={} bytes; continuation={} bytes; explicit repro={} bytes",
            bytes("stall"), bytes("hang_continues"), bytes("repro"));
        runtime.clean(false);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn checkpoint_is_recent_bounded_context_and_not_written_every_two_seconds() {
        let root = std::env::temp_dir().join(unique_id("living-telemetry-light-checkpoint"));
        let mut runtime = Runtime::new(launch(root.clone()));
        runtime.records = (1..=1_000).map(test_record).collect();
        let now = unix_ms();
        runtime.snapshot.unix_ms = now;
        runtime.snapshot.busy = Some(BusyState { episode: 1, since_unix_ms: now,
            last_progress_unix_ms: now, activity: "test".into() });
        let prior = now - 2_500;
        runtime.last_checkpoint_ms = prior;
        runtime.tick();
        assert_eq!(runtime.last_checkpoint_ms, prior);
        runtime.last_checkpoint_ms = now - ACTIVE_CHECKPOINT_MS - 1;
        runtime.tick();
        let checkpoint: RunCheckpoint = serde_json::from_slice(&fs::read(&runtime.checkpoint_path).unwrap()).unwrap();
        assert_eq!(checkpoint.records.len(), CHECKPOINT_RECORDS);
        assert_eq!(checkpoint.records.first().unwrap().seq(), 1_001 - CHECKPOINT_RECORDS as u64);
        assert_eq!(checkpoint.records.last().unwrap().seq(), 1_000);
        runtime.clean(false);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn old_checkpoint_launch_metadata_gets_safe_dump_defaults() {
        let root = std::env::temp_dir().join(unique_id("living-telemetry-old-launch"));
        let mut value = serde_json::to_value(launch(root)).unwrap();
        value.as_object_mut().unwrap().remove("hang_dump_limit");
        value.as_object_mut().unwrap().remove("hang_dump_cooldown_ms");
        let recovered: WatchdogLaunch = serde_json::from_value(value).unwrap();
        assert_eq!(recovered.hang_dump_limit, 2);
        assert_eq!(recovered.hang_dump_cooldown_ms, 600_000);
    }

    #[test]
    fn session_record_dedup_cache_is_bounded_and_failed_enqueue_does_not_mark_sent() {
        let root = std::env::temp_dir().join(unique_id("living-telemetry-sent-bound"));
        let mut runtime = Runtime::new(launch(root.clone()));
        runtime.emit("performance", "slow_intervals", Vec::new(), Vec::new(),
            (1..=SENT_RECORD_CACHE as u64 + 50).map(test_record).collect());
        assert_eq!(runtime.sent_records.len(), SENT_RECORD_CACHE);
        assert_eq!(runtime.sent_order.len(), SENT_RECORD_CACHE);
        assert!(!runtime.sent_records.contains(&1));
        assert!(runtime.sent_records.contains(&(SENT_RECORD_CACHE as u64 + 50)));
        runtime.spool = None;
        runtime.emit("performance", "slow_intervals", Vec::new(), Vec::new(), vec![test_record(1_000_000)]);
        assert!(!runtime.sent_records.contains(&1_000_000));
        runtime.clean(false);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn exact_frame_records_enter_performance_batch() {
        let root = std::env::temp_dir().join(unique_id("living-telemetry-watchdog"));
        let mut runtime = Runtime::new(launch(root.clone()));
        let now = unix_ms();
        runtime.accept_snapshot(Snapshot {
            unix_ms: now,
            uptime_ms: 10,
            frame_budget_us: 16_667,
            busy: None,
            state: Vec::new(),
            records: vec![Record::Frame(FrameRecord {
                seq: 1,
                frame: 1,
                uptime_us: 10_000,
                unix_ms: now,
                budget_us: 16_667,
                total_us: 22_000,
                request_wait_us: None,
                input_wait_us: None,
                active_interval_us: None,
                missed: vec!["cpu".to_string()],
                phases: vec![Phase {
                    name: "render".to_string(),
                    duration_us: 20_000,
                }],
                fields: Vec::new(),
            })],
            frame_summary: FrameSummary::default(),
            recorder_dropped: 0,
        });
        assert_eq!(runtime.performance.len(), 1);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn explicit_report_spools_current_state_and_context() {
        let root = std::env::temp_dir().join(unique_id("living-telemetry-explicit"));
        let mut runtime = Runtime::new(launch(root.clone()));
        let now = unix_ms();
        runtime.accept_snapshot(Snapshot {
            unix_ms: now,
            uptime_ms: 10,
            frame_budget_us: 16_667,
            busy: None,
            state: vec![Field::new("seed", 60021u32)],
            records: Vec::new(),
            frame_summary: FrameSummary::default(),
            recorder_dropped: 0,
        });
        runtime.report(ReportRequest {
            topic: "feedback".to_string(),
            kind: "repro".to_string(),
            fields: vec![Field::new("position_x", 12.5f64)],
        });
        let reports = fs::read_dir(root.join("spool"))
            .unwrap()
            .filter_map(Result::ok)
            .filter_map(|entry| fs::read(entry.path()).ok())
            .filter_map(|bytes| serde_json::from_slice::<SpoolEnvelope>(&bytes).ok())
            .collect::<Vec<_>>();
        let report = reports.iter().find(|report| report.report.kind == "repro").unwrap();
        assert_eq!(report.report.topic, "feedback");
        assert_eq!(report.report.state, vec![Field::new("seed", 60021i64)]);
        assert_eq!(report.report.fields, vec![Field::new("position_x", 12.5f64)]);
        runtime.clean(false);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn active_callback_over_threshold_spools_stall_report() {
        let root = std::env::temp_dir().join(unique_id("living-telemetry-stall"));
        let mut runtime = Runtime::new(launch(root.clone()));
        let now = unix_ms();
        runtime.accept_snapshot(Snapshot {
            unix_ms: now,
            uptime_ms: 300,
            frame_budget_us: 16_667,
            busy: Some(BusyState {
                episode: 1,
                since_unix_ms: now - 300,
                last_progress_unix_ms: now - 300,
                activity: "test.blocked".to_string(),
            }),
            state: Vec::new(),
            records: Vec::new(),
            frame_summary: FrameSummary::default(),
            recorder_dropped: 0,
        });
        let reports = fs::read_dir(root.join("spool"))
            .unwrap()
            .filter_map(Result::ok)
            .filter_map(|entry| fs::read(entry.path()).ok())
            .filter_map(|bytes| serde_json::from_slice::<SpoolEnvelope>(&bytes).ok())
            .collect::<Vec<_>>();
        assert!(reports.iter().any(|report| report.report.kind == "stall"));
        runtime.clean(false);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn stale_snapshot_does_not_report_a_ui_hang() {
        let root = std::env::temp_dir().join(unique_id("living-telemetry-stale-snapshot"));
        let mut runtime = Runtime::new(launch(root.clone()));
        let now = unix_ms();
        runtime.accept_snapshot(Snapshot {
            unix_ms: now - SNAPSHOT_FRESH_MS - 1,
            uptime_ms: 300,
            frame_budget_us: 16_667,
            busy: Some(BusyState {
                episode: 1,
                since_unix_ms: now - 10_000,
                last_progress_unix_ms: now - 10_000,
                activity: "test.stale".to_string(),
            }),
            state: Vec::new(),
            records: Vec::new(),
            frame_summary: FrameSummary::default(),
            recorder_dropped: 0,
        });
        let reports = fs::read_dir(root.join("spool"))
            .unwrap()
            .filter_map(Result::ok)
            .filter_map(|entry| fs::read(entry.path()).ok())
            .filter_map(|bytes| serde_json::from_slice::<SpoolEnvelope>(&bytes).ok())
            .collect::<Vec<_>>();
        assert!(!reports.iter().any(|report| {
            matches!(report.report.kind.as_str(), "stall" | "hang" | "hang_continues")
        }));
        runtime.clean(false);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn queued_short_callback_is_not_a_three_second_hang() {
        let root = std::env::temp_dir().join(unique_id("living-telemetry-queued"));
        let mut runtime = Runtime::new(launch(root.clone()));
        let now = unix_ms();
        runtime.accept_snapshot(Snapshot {
            unix_ms: now - 2_900,
            uptime_ms: 100,
            frame_budget_us: 16_667,
            busy: Some(BusyState {
                episode: 1,
                since_unix_ms: now - 2_925,
                last_progress_unix_ms: now - 2_925,
                activity: "frame.surface_acquire".to_string(),
            }),
            state: Vec::new(),
            records: Vec::new(),
            frame_summary: FrameSummary::default(),
            recorder_dropped: 0,
        });
        runtime.check_stall(now);
        assert!(!runtime.incident.as_ref().unwrap().stall_reported);
        assert!(!runtime.incident.as_ref().unwrap().hang_reported);
        // Waiting for the next heartbeat is not additional UI-stall evidence.
        runtime.check_stall(now + 50);
        assert!(!runtime.incident.as_ref().unwrap().stall_reported);
        runtime.clean(false);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn fresh_heartbeats_still_detect_a_real_ui_hang() {
        let root = std::env::temp_dir().join(unique_id("living-telemetry-real-hang"));
        let mut runtime = Runtime::new(launch(root.clone()));
        let now = unix_ms();
        runtime.accept_snapshot(Snapshot {
            unix_ms: now,
            uptime_ms: 2_100,
            frame_budget_us: 16_667,
            busy: Some(BusyState {
                episode: 1,
                since_unix_ms: now - 2_100,
                last_progress_unix_ms: now - 2_100,
                activity: "test.blocked".to_string(),
            }),
            state: Vec::new(),
            records: Vec::new(),
            frame_summary: FrameSummary::default(),
            recorder_dropped: 0,
        });
        assert!(runtime.incident.as_ref().unwrap().hang_reported);
        runtime.clean(false);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn recovery_only_reports_after_stall_threshold_was_reached() {
        let root = std::env::temp_dir().join(unique_id("living-telemetry-recovery"));
        let mut runtime = Runtime::new(launch(root.clone()));
        let now = unix_ms();
        runtime.accept_snapshot(Snapshot {
            unix_ms: now,
            uptime_ms: 10,
            frame_budget_us: 16_667,
            busy: Some(BusyState {
                episode: 1,
                since_unix_ms: now - 100,
                last_progress_unix_ms: now - 100,
                activity: "test".to_string(),
            }),
            state: Vec::new(),
            records: Vec::new(),
            frame_summary: FrameSummary::default(),
            recorder_dropped: 0,
        });
        runtime.accept_snapshot(Snapshot {
            unix_ms: now + 110,
            uptime_ms: 120,
            frame_budget_us: 16_667,
            busy: None,
            state: Vec::new(),
            records: Vec::new(),
            frame_summary: FrameSummary::default(),
            recorder_dropped: 0,
        });
        assert!(runtime.incident.is_none());
        let _ = fs::remove_dir_all(root);
    }
}
