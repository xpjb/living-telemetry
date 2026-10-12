use std::collections::{HashMap, VecDeque};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::ChildStdin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread::{self, JoinHandle, ThreadId};
use std::time::{Duration, Instant};

use crate::platform;
use crate::protocol::{
    BusyState, EventRecord, Field, FrameRecord, FrameSummary, Phase, Record, Report,
    SCHEMA_VERSION, Snapshot, Value, WatchMessage, WatchdogLaunch, unique_id, unix_ms,
};
use crate::spool::Spool;
use crate::watchdog;

static CLIENT: OnceLock<Arc<Client>> = OnceLock::new();

pub struct Config {
    pub app: String,
    pub version: String,
    pub data_dir: PathBuf,
    pub endpoint: Option<String>,
    pub ring_capacity: usize,
    pub spool_max_bytes: u64,
    pub frame_budget: Duration,
    pub slow_scope: Duration,
    pub stall_after: Duration,
    pub hang_after: Duration,
}

impl Config {
    pub fn new(
        app: impl Into<String>,
        version: impl Into<String>,
        data_dir: impl Into<PathBuf>,
    ) -> Self {
        Self {
            app: app.into(),
            version: version.into(),
            data_dir: data_dir.into(),
            endpoint: None,
            ring_capacity: 4_096,
            spool_max_bytes: 128 * 1024 * 1024,
            frame_budget: Duration::from_nanos(16_666_667),
            slow_scope: Duration::from_millis(2),
            stall_after: Duration::from_millis(250),
            hang_after: Duration::from_secs(2),
        }
    }
}

struct Metadata {
    app: String,
    version: String,
    device: String,
    run_id: String,
    pid: u32,
    start_unix_ms: u64,
    data_dir: PathBuf,
    endpoint: Option<String>,
    native_dump_path: PathBuf,
    spool_max_bytes: u64,
}

struct Shared {
    records: VecDeque<Record>,
    state: Vec<Field>,
    frame_summary: FrameSummary,
}

struct Client {
    metadata: Metadata,
    started: Instant,
    ui_thread: ThreadId,
    ring_capacity: usize,
    slow_scope_us: u64,
    shared: Mutex<Shared>,
    activities: Mutex<HashMap<u64, String>>,
    next_activity: AtomicU64,
    sequence: AtomicU64,
    recorder_dropped: AtomicU64,
    activity: AtomicU64,
    activity_started_us: AtomicU64,
    busy_depth: AtomicU32,
    busy_episode: AtomicU64,
    busy_since_us: AtomicU64,
    last_progress_us: AtomicU64,
    redraw_requested_us: AtomicU64,
    input_received_us: AtomicU64,
    frame_active: AtomicBool,
    next_frame_expected: AtomicBool,
    last_frame_start_us: AtomicU64,
    next_frame: AtomicU64,
    frame_budget_us: AtomicU64,
    shutdown: AtomicBool,
    clean: AtomicBool,
    report_wait: Mutex<()>,
    report_signal: Condvar,
    reporter: Mutex<Option<JoinHandle<()>>>,
}

pub fn init(config: Config) -> Result<(), String> {
    if CLIENT.get().is_some() {
        return Ok(());
    }
    let root = config.data_dir.join("telemetry");
    std::fs::create_dir_all(root.join("spool")).map_err(|err| err.to_string())?;
    std::fs::create_dir_all(root.join("attachments")).map_err(|err| err.to_string())?;
    std::fs::create_dir_all(root.join("runs")).map_err(|err| err.to_string())?;
    let device = load_or_create_device(&root)?;
    let run_id = unique_id("run");
    let native_dump_path = root
        .join("attachments")
        .join(format!("{run_id}-native-crash.dmp"));
    let metadata = Metadata {
        app: config.app,
        version: config.version,
        device,
        run_id,
        pid: std::process::id(),
        start_unix_ms: unix_ms(),
        data_dir: root,
        endpoint: config.endpoint,
        native_dump_path,
        spool_max_bytes: config.spool_max_bytes,
    };
    let client = Arc::new(Client {
        metadata,
        started: Instant::now(),
        ui_thread: thread::current().id(),
        ring_capacity: config.ring_capacity.max(64),
        slow_scope_us: duration_us(config.slow_scope),
        shared: Mutex::new(Shared {
            records: VecDeque::with_capacity(config.ring_capacity.min(4_096)),
            state: Vec::new(),
            frame_summary: FrameSummary::default(),
        }),
        activities: Mutex::new(HashMap::new()),
        next_activity: AtomicU64::new(1),
        sequence: AtomicU64::new(1),
        recorder_dropped: AtomicU64::new(0),
        activity: AtomicU64::new(0),
        activity_started_us: AtomicU64::new(0),
        busy_depth: AtomicU32::new(0),
        busy_episode: AtomicU64::new(0),
        busy_since_us: AtomicU64::new(0),
        last_progress_us: AtomicU64::new(0),
        redraw_requested_us: AtomicU64::new(0),
        input_received_us: AtomicU64::new(0),
        frame_active: AtomicBool::new(false),
        next_frame_expected: AtomicBool::new(false),
        last_frame_start_us: AtomicU64::new(0),
        next_frame: AtomicU64::new(1),
        frame_budget_us: AtomicU64::new(duration_us(config.frame_budget).max(1)),
        shutdown: AtomicBool::new(false),
        clean: AtomicBool::new(false),
        report_wait: Mutex::new(()),
        report_signal: Condvar::new(),
        reporter: Mutex::new(None),
    });
    CLIENT
        .set(client.clone())
        .map_err(|_| "telemetry already initialized".to_string())?;
    let _ = platform::install_native_crash_handler(&client.metadata.native_dump_path);
    let launch = WatchdogLaunch {
        app: client.metadata.app.clone(),
        version: client.metadata.version.clone(),
        device: client.metadata.device.clone(),
        run_id: client.metadata.run_id.clone(),
        parent_pid: client.metadata.pid,
        parent_start_token: platform::process_sample(client.metadata.pid).start_token,
        start_unix_ms: client.metadata.start_unix_ms,
        data_dir: client.metadata.data_dir.clone(),
        endpoint: client.metadata.endpoint.clone(),
        native_dump_path: client.metadata.native_dump_path.clone(),
        ring_capacity: client.ring_capacity,
        spool_max_bytes: client.metadata.spool_max_bytes,
        stall_ms: config.stall_after.as_millis().min(u128::from(u64::MAX)) as u64,
        hang_ms: config.hang_after.as_millis().min(u128::from(u64::MAX)) as u64,
    };
    let reporter_client = client.clone();
    let reporter = thread::Builder::new()
        .name("living-telemetry-reporter".to_string())
        .spawn(move || reporter_loop(reporter_client, launch))
        .map_err(|err| format!("start telemetry reporter: {err}"))?;
    *client
        .reporter
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(reporter);
    event(
        "runtime",
        "started",
        vec![
            Field::new("pid", client.metadata.pid),
            Field::new("device", client.metadata.device.clone()),
        ],
    );
    Ok(())
}

pub fn shutdown() {
    let Some(client) = CLIENT.get() else {
        return;
    };
    client.clean.store(true, Ordering::Release);
    client.shutdown.store(true, Ordering::Release);
    client.report_signal.notify_one();
    if let Some(handle) = client
        .reporter
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take()
    {
        let _ = handle.join();
    }
}

pub fn report_panic(location: &str, payload: &str, backtrace: &str) {
    let Some(client) = CLIENT.get() else {
        return;
    };
    let now_us = client.now_us();
    let (state, records, frame_summary) = client.shared.try_lock().map_or_else(
        |_| (Vec::new(), Vec::new(), FrameSummary::default()),
        |shared| {
            (
                shared.state.clone(),
                shared.records.iter().cloned().collect(),
                shared.frame_summary.clone(),
            )
        },
    );
    let busy = (client.busy_depth.load(Ordering::Acquire) > 0).then(|| {
        let since = decode_time(client.busy_since_us.load(Ordering::Acquire)).unwrap_or(now_us);
        let progress = decode_time(client.last_progress_us.load(Ordering::Acquire)).unwrap_or(since);
        let activity_id = client.activity.load(Ordering::Acquire);
        let activity = client
            .activities
            .try_lock()
            .ok()
            .and_then(|activities| activities.get(&activity_id).cloned())
            .unwrap_or_else(|| "ui.callback".to_string());
        BusyState {
            episode: client.busy_episode.load(Ordering::Acquire),
            since_unix_ms: client.unix_for_us(since),
            last_progress_unix_ms: client.unix_for_us(progress),
            activity,
        }
    });
    let snapshot = Snapshot {
        unix_ms: client.unix_for_us(now_us),
        uptime_ms: now_us / 1_000,
        frame_budget_us: client.frame_budget_us.load(Ordering::Acquire),
        busy,
        state,
        records,
        frame_summary,
        recorder_dropped: client.recorder_dropped.load(Ordering::Acquire),
    };
    let report = client.report(
        "crash",
        "panic",
        snapshot,
        vec![
            Field::new("location", location.to_string()),
            Field::new("payload", payload.to_string()),
            Field::new("backtrace", backtrace.to_string()),
        ],
        None,
    );
    if let Ok(spool) = Spool::new(
        client.metadata.data_dir.join("spool"),
        client.metadata.spool_max_bytes,
        client.metadata.endpoint.as_deref(),
    ) {
        let _ = spool.enqueue(report, Vec::new());
    }
}

pub fn set_frame_budget(budget: Duration) {
    if let Some(client) = CLIENT.get() {
        client
            .frame_budget_us
            .store(duration_us(budget).max(1), Ordering::Release);
    }
}

pub fn frame_budget() -> Duration {
    CLIENT
        .get()
        .map(|client| Duration::from_micros(client.frame_budget_us.load(Ordering::Acquire)))
        .unwrap_or_else(|| Duration::from_nanos(16_666_667))
}

pub fn register_activity(name: &'static str) -> u64 {
    let Some(client) = CLIENT.get() else {
        return 0;
    };
    let id = client.next_activity.fetch_add(1, Ordering::Relaxed);
    client
        .activities
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(id, name.to_string());
    id
}

#[doc(hidden)]
pub fn scope_registered(
    id: u64,
    category: &'static str,
    name: &'static str,
) -> Scope {
    let Some(client) = CLIENT.get() else {
        return Scope::inactive();
    };
    let ui = thread::current().id() == client.ui_thread;
    let now_us = client.now_us();
    let previous = if ui {
        let previous_id = client.activity.swap(id, Ordering::AcqRel);
        let previous_started = client.activity_started_us.swap(now_us + 1, Ordering::AcqRel);
        client.last_progress_us.store(now_us + 1, Ordering::Release);
        Some((previous_id, previous_started))
    } else {
        None
    };
    Scope {
        client: Some(client.clone()),
        category,
        name,
        start: Instant::now(),
        ui_previous: previous,
    }
}

#[doc(hidden)]
pub fn busy_registered(
    id: u64,
    category: &'static str,
    name: &'static str,
) -> BusyGuard {
    let Some(client) = CLIENT.get() else {
        return BusyGuard::inactive();
    };
    let now_us = client.now_us();
    if client.busy_depth.fetch_add(1, Ordering::AcqRel) == 0 {
        client.busy_episode.fetch_add(1, Ordering::AcqRel);
        client.busy_since_us.store(now_us + 1, Ordering::Release);
        client.last_progress_us.store(now_us + 1, Ordering::Release);
        client.report_signal.notify_one();
    }
    BusyGuard {
        client: Some(client.clone()),
        scope: Some(scope_registered(id, category, name)),
        category,
        name,
        start: Instant::now(),
    }
}

pub struct Scope {
    client: Option<Arc<Client>>,
    category: &'static str,
    name: &'static str,
    start: Instant,
    ui_previous: Option<(u64, u64)>,
}

impl Scope {
    fn inactive() -> Self {
        Self {
            client: None,
            category: "",
            name: "",
            start: Instant::now(),
            ui_previous: None,
        }
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        let Some(client) = &self.client else {
            return;
        };
        let duration_us = duration_us(self.start.elapsed());
        if let Some((previous_id, previous_started)) = self.ui_previous {
            client.activity.store(previous_id, Ordering::Release);
            client
                .activity_started_us
                .store(previous_started, Ordering::Release);
            client
                .last_progress_us
                .store(client.now_us() + 1, Ordering::Release);
        }
        if duration_us >= client.slow_scope_us {
            client.record_event(
                self.category,
                self.name,
                Some(duration_us),
                Vec::new(),
            );
        }
    }
}

pub struct BusyGuard {
    client: Option<Arc<Client>>,
    scope: Option<Scope>,
    category: &'static str,
    name: &'static str,
    start: Instant,
}

impl BusyGuard {
    fn inactive() -> Self {
        Self {
            client: None,
            scope: None,
            category: "",
            name: "",
            start: Instant::now(),
        }
    }
}

impl Drop for BusyGuard {
    fn drop(&mut self) {
        self.scope.take();
        let Some(client) = &self.client else {
            return;
        };
        let depth = client.busy_depth.fetch_sub(1, Ordering::AcqRel);
        if depth <= 1 {
            client.busy_since_us.store(0, Ordering::Release);
            client.last_progress_us.store(0, Ordering::Release);
            client.activity.store(0, Ordering::Release);
            client.activity_started_us.store(0, Ordering::Release);
        }
        let duration_us = duration_us(self.start.elapsed());
        let budget_us = client.frame_budget_us.load(Ordering::Acquire);
        if duration_us > budget_us {
            client.record_event(
                self.category,
                "callback_over_budget",
                Some(duration_us),
                vec![
                    Field::new("callback", self.name),
                    Field::new("budget_us", budget_us),
                ],
            );
        }
    }
}

pub fn event(category: &'static str, name: &'static str, fields: Vec<Field>) {
    if let Some(client) = CLIENT.get() {
        client.record_event(category, name, None, fields);
    }
}

pub fn set_state(fields: Vec<Field>) {
    let Some(client) = CLIENT.get() else {
        return;
    };
    match client.shared.try_lock() {
        Ok(mut shared) => shared.state = fields,
        Err(_) => {
            client.recorder_dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

pub fn redraw_requested() {
    let Some(client) = CLIENT.get() else {
        return;
    };
    let now = client.now_us() + 1;
    let _ = client
        .redraw_requested_us
        .compare_exchange(0, now, Ordering::AcqRel, Ordering::Acquire);
    if client.frame_active.load(Ordering::Acquire) {
        client.next_frame_expected.store(true, Ordering::Release);
    }
}

pub fn input_received() -> bool {
    let Some(client) = CLIENT.get() else {
        return false;
    };
    let now = client.now_us() + 1;
    client
        .input_received_us
        .compare_exchange(0, now, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

pub fn clear_pending_input() {
    if let Some(client) = CLIENT.get() {
        client.input_received_us.store(0, Ordering::Release);
    }
}

pub fn clear_pending_frame() {
    if let Some(client) = CLIENT.get() {
        client.redraw_requested_us.store(0, Ordering::Release);
        client.input_received_us.store(0, Ordering::Release);
        client.next_frame_expected.store(false, Ordering::Release);
    }
}

pub struct Frame {
    client: Option<Arc<Client>>,
    frame: u64,
    start: Instant,
    start_us: u64,
    request_wait_us: Option<u64>,
    input_wait_us: Option<u64>,
    active_interval_us: Option<u64>,
    current_phase: Option<&'static str>,
    phase_start: Instant,
    phases: Vec<Phase>,
    fields: Vec<Field>,
    finished: bool,
}

impl Frame {
    pub fn start() -> Self {
        let Some(client) = CLIENT.get() else {
            return Self::inactive();
        };
        let start = Instant::now();
        let start_us = client.now_us();
        client.frame_active.store(true, Ordering::Release);
        let request = decode_time(client.redraw_requested_us.swap(0, Ordering::AcqRel));
        let input = decode_time(client.input_received_us.swap(0, Ordering::AcqRel));
        let cadence_expected = client.next_frame_expected.swap(false, Ordering::AcqRel);
        let previous_start = client
            .last_frame_start_us
            .swap(start_us + 1, Ordering::AcqRel);
        Self {
            client: Some(client.clone()),
            frame: client.next_frame.fetch_add(1, Ordering::Relaxed),
            start,
            start_us,
            request_wait_us: request.map(|request| start_us.saturating_sub(request)),
            input_wait_us: input.map(|input| start_us.saturating_sub(input)),
            active_interval_us: (cadence_expected && previous_start > 0)
                .then(|| start_us.saturating_sub(previous_start - 1)),
            current_phase: None,
            phase_start: start,
            phases: Vec::with_capacity(12),
            fields: Vec::new(),
            finished: false,
        }
    }

    fn inactive() -> Self {
        let now = Instant::now();
        Self {
            client: None,
            frame: 0,
            start: now,
            start_us: 0,
            request_wait_us: None,
            input_wait_us: None,
            active_interval_us: None,
            current_phase: None,
            phase_start: now,
            phases: Vec::new(),
            fields: Vec::new(),
            finished: false,
        }
    }

    pub fn phase(&mut self, name: &'static str) {
        self.close_phase();
        self.current_phase = Some(name);
        self.phase_start = Instant::now();
    }

    pub fn field(&mut self, key: impl Into<String>, value: impl Into<Value>) {
        self.fields.push(Field::new(key, value));
    }

    pub fn finish(mut self) {
        self.finish_inner();
    }

    fn close_phase(&mut self) {
        if let Some(name) = self.current_phase.take() {
            self.phases.push(Phase {
                name: name.to_string(),
                duration_us: duration_us(self.phase_start.elapsed()),
            });
        }
    }

    fn finish_inner(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        self.close_phase();
        let Some(client) = &self.client else {
            return;
        };
        let total_us = duration_us(self.start.elapsed());
        let budget_us = client.frame_budget_us.load(Ordering::Acquire).max(1);
        let missed = classify_frame(
            total_us,
            self.request_wait_us,
            self.input_wait_us,
            self.active_interval_us,
            &self.phases,
            budget_us,
        );
        let dropped = !missed.is_empty();
        if let Ok(mut shared) = client.shared.try_lock() {
            shared.frame_summary.record(
                total_us,
                self.request_wait_us,
                self.input_wait_us,
                self.active_interval_us,
                dropped,
            );
            if dropped {
                let seq = client.sequence.fetch_add(1, Ordering::Relaxed);
                let record = Record::Frame(FrameRecord {
                    seq,
                    frame: self.frame,
                    uptime_us: self.start_us,
                    unix_ms: client.unix_for_us(self.start_us),
                    budget_us,
                    total_us,
                    request_wait_us: self.request_wait_us,
                    input_wait_us: self.input_wait_us,
                    active_interval_us: self.active_interval_us,
                    missed,
                    phases: std::mem::take(&mut self.phases),
                    fields: std::mem::take(&mut self.fields),
                });
                client.push_record(&mut shared, record);
            }
        } else {
            client.recorder_dropped.fetch_add(1, Ordering::Relaxed);
        }
        client.frame_active.store(false, Ordering::Release);
        client
            .last_progress_us
            .store(client.now_us() + 1, Ordering::Release);
    }
}

impl Drop for Frame {
    fn drop(&mut self) {
        self.finish_inner();
    }
}

impl Client {
    fn now_us(&self) -> u64 {
        duration_us(self.started.elapsed())
    }

    fn unix_for_us(&self, uptime_us: u64) -> u64 {
        self.metadata
            .start_unix_ms
            .saturating_add(uptime_us / 1_000)
    }

    fn record_event(
        &self,
        category: &str,
        name: &str,
        duration_us: Option<u64>,
        fields: Vec<Field>,
    ) {
        let uptime_us = self.now_us();
        let seq = self.sequence.fetch_add(1, Ordering::Relaxed);
        let record = Record::Event(EventRecord {
            seq,
            uptime_us,
            unix_ms: self.unix_for_us(uptime_us),
            thread: if thread::current().id() == self.ui_thread {
                "ui".to_string()
            } else {
                thread::current()
                    .name()
                    .unwrap_or("worker")
                    .to_string()
            },
            category: category.to_string(),
            name: name.to_string(),
            duration_us,
            fields,
        });
        if let Ok(mut shared) = self.shared.try_lock() {
            self.push_record(&mut shared, record);
        } else {
            self.recorder_dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn push_record(&self, shared: &mut Shared, record: Record) {
        if shared.records.len() == self.ring_capacity {
            shared.records.pop_front();
            self.recorder_dropped.fetch_add(1, Ordering::Relaxed);
        }
        shared.records.push_back(record);
    }

    fn snapshot_since(&self, last_seq: u64) -> Snapshot {
        let (state, records, frame_summary) = match self.shared.lock() {
            Ok(shared) => (
                shared.state.clone(),
                shared
                    .records
                    .iter()
                    .filter(|record| record.seq() > last_seq)
                    .cloned()
                    .collect(),
                shared.frame_summary.clone(),
            ),
            Err(poisoned) => {
                let shared = poisoned.into_inner();
                (
                    shared.state.clone(),
                    shared
                        .records
                        .iter()
                        .filter(|record| record.seq() > last_seq)
                        .cloned()
                        .collect(),
                    shared.frame_summary.clone(),
                )
            }
        };
        let now_us = self.now_us();
        let busy = if self.busy_depth.load(Ordering::Acquire) > 0 {
            let since = decode_time(self.busy_since_us.load(Ordering::Acquire)).unwrap_or(now_us);
            let progress = decode_time(self.last_progress_us.load(Ordering::Acquire)).unwrap_or(since);
            let activity_id = self.activity.load(Ordering::Acquire);
            let activity = self
                .activities
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get(&activity_id)
                .cloned()
                .unwrap_or_else(|| "ui.callback".to_string());
            Some(BusyState {
                episode: self.busy_episode.load(Ordering::Acquire),
                since_unix_ms: self.unix_for_us(since),
                last_progress_unix_ms: self.unix_for_us(progress),
                activity,
            })
        } else {
            None
        };
        Snapshot {
            unix_ms: self.unix_for_us(now_us),
            uptime_ms: now_us / 1_000,
            frame_budget_us: self.frame_budget_us.load(Ordering::Acquire),
            busy,
            state,
            records,
            frame_summary,
            recorder_dropped: self.recorder_dropped.load(Ordering::Acquire),
        }
    }

    fn report(
        &self,
        topic: &str,
        kind: &str,
        snapshot: Snapshot,
        fields: Vec<Field>,
        process: Option<crate::protocol::ProcessSample>,
    ) -> Report {
        Report {
            schema: SCHEMA_VERSION,
            report_id: unique_id(kind),
            topic: topic.to_string(),
            kind: kind.to_string(),
            app: self.metadata.app.clone(),
            version: self.metadata.version.clone(),
            device: self.metadata.device.clone(),
            run_id: self.metadata.run_id.clone(),
            pid: self.metadata.pid,
            unix_ms: snapshot.unix_ms,
            uptime_ms: snapshot.uptime_ms,
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            process,
            state: snapshot.state,
            frame_summary: snapshot.frame_summary,
            recorder_dropped: snapshot.recorder_dropped,
            records: snapshot.records,
            fields,
            attachments: Vec::new(),
        }
    }
}

fn reporter_loop(client: Arc<Client>, launch: WatchdogLaunch) {
    let mut child = watchdog::spawn(&launch).ok();
    let mut writer = child
        .as_mut()
        .and_then(|(_, stdin)| stdin.take())
        .map(BufWriter::new);
    let mut local = writer
        .is_none()
        .then(|| watchdog::Runtime::new(launch.clone()));
    let mut last_seq = 0;
    loop {
        let snapshot = client.snapshot_since(last_seq);
        if let Some(seq) = snapshot.records.last().map(Record::seq) {
            last_seq = last_seq.max(seq);
        }
        let busy = snapshot.busy.is_some();
        let message = WatchMessage::Snapshot(snapshot.clone());
        let delivered = writer
            .as_mut()
            .is_some_and(|writer| write_message(writer, &message).is_ok());
        if !delivered {
            writer = None;
            let runtime = local.get_or_insert_with(|| watchdog::Runtime::new(launch.clone()));
            runtime.accept_snapshot(snapshot);
            runtime.tick();
        }
        if client.shutdown.load(Ordering::Acquire) {
            let clean = client.clean.load(Ordering::Acquire);
            if clean {
                if let Some(writer) = writer.as_mut() {
                    let _ = write_message(writer, &WatchMessage::Clean { unix_ms: unix_ms() });
                }
                if let Some(runtime) = local.as_mut() {
                    runtime.clean();
                }
            }
            break;
        }
        let delay = if busy {
            Duration::from_millis(100)
        } else {
            Duration::from_secs(1)
        };
        let guard = client
            .report_wait
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _ = client.report_signal.wait_timeout(guard, delay);
    }
    drop(writer);
    if let Some((mut child, _)) = child.take() {
        let deadline = Instant::now() + Duration::from_millis(500);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break;
                }
            }
        }
    }
}

fn write_message(writer: &mut BufWriter<ChildStdin>, message: &WatchMessage) -> Result<(), String> {
    serde_json::to_writer(&mut *writer, message).map_err(|err| err.to_string())?;
    writer.write_all(b"\n").map_err(|err| err.to_string())?;
    writer.flush().map_err(|err| err.to_string())
}

fn load_or_create_device(root: &Path) -> Result<String, String> {
    let path = root.join("device-id");
    if let Ok(value) = std::fs::read_to_string(&path) {
        let value = value.trim();
        if !value.is_empty() {
            return Ok(value.to_string());
        }
    }
    let value = unique_id("device");
    std::fs::write(&path, format!("{value}\n")).map_err(|err| err.to_string())?;
    Ok(value)
}

fn classify_frame(
    total_us: u64,
    request_wait_us: Option<u64>,
    input_wait_us: Option<u64>,
    active_interval_us: Option<u64>,
    phases: &[Phase],
    budget_us: u64,
) -> Vec<String> {
    let latency_limit = budget_us.saturating_mul(3) / 2;
    let cadence_limit = budget_us.saturating_add((budget_us / 10).max(2_000));
    let mut missed = Vec::new();
    if total_us > budget_us {
        missed.push("cpu".to_string());
    }
    if request_wait_us.is_some_and(|duration| duration > latency_limit) {
        missed.push("redraw_latency".to_string());
    }
    if input_wait_us.is_some_and(|duration| duration > latency_limit) {
        missed.push("input_latency".to_string());
    }
    if active_interval_us.is_some_and(|duration| duration > cadence_limit) {
        missed.push("cadence".to_string());
    }
    if phases
        .iter()
        .any(|phase| phase.duration_us > budget_us)
    {
        missed.push("phase".to_string());
    }
    missed
}

fn duration_us(duration: Duration) -> u64 {
    duration.as_micros().min(u128::from(u64::MAX)) as u64
}

fn decode_time(value: u64) -> Option<u64> {
    (value > 0).then(|| value - 1)
}

#[macro_export]
macro_rules! scope {
    ($category:literal, $name:literal) => {{
        static ID: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
        $crate::scope_registered(
            *ID.get_or_init(|| $crate::register_activity(concat!($category, ".", $name))),
            $category,
            $name,
        )
    }};
}

#[macro_export]
macro_rules! busy {
    ($category:literal, $name:literal) => {{
        static ID: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
        $crate::busy_registered(
            *ID.get_or_init(|| $crate::register_activity(concat!($category, ".", $name))),
            $category,
            $name,
        )
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_timestamp_decodes_as_missing() {
        assert_eq!(decode_time(0), None);
        assert_eq!(decode_time(1), Some(0));
    }

    #[test]
    fn frame_classifier_keeps_every_drop_reason() {
        let phases = vec![Phase {
            name: "render".to_string(),
            duration_us: 20_000,
        }];
        assert_eq!(
            classify_frame(
                20_000,
                Some(30_000),
                Some(31_000),
                Some(21_000),
                &phases,
                16_667,
            ),
            ["cpu", "redraw_latency", "input_latency", "cadence", "phase"]
        );
        assert!(classify_frame(4_000, None, None, None, &[], 16_667).is_empty());
    }

    #[test]
    fn frame_summary_keeps_every_bucket_and_drop_count() {
        let mut summary = FrameSummary::default();
        summary.record(7_000, None, None, None, false);
        summary.record(17_000, Some(30_000), None, None, true);
        summary.record(300_000, None, None, None, true);
        assert_eq!(summary.frames, 3);
        assert_eq!(summary.dropped_frames, 2);
        assert_eq!(summary.buckets[0], 1);
        assert_eq!(summary.buckets[2], 1);
        assert_eq!(summary.buckets[8], 1);
        assert_eq!(summary.max_request_wait_us, 30_000);
    }
}
