use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Value {
    Bool(bool),
    I64(i64),
    U64(u64),
    F64(f64),
    Text(String),
}

impl From<bool> for Value {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<i32> for Value {
    fn from(value: i32) -> Self {
        Self::I64(i64::from(value))
    }
}

impl From<i64> for Value {
    fn from(value: i64) -> Self {
        Self::I64(value)
    }
}

impl From<u32> for Value {
    fn from(value: u32) -> Self {
        Self::U64(u64::from(value))
    }
}

impl From<u64> for Value {
    fn from(value: u64) -> Self {
        Self::U64(value)
    }
}

impl From<usize> for Value {
    fn from(value: usize) -> Self {
        Self::U64(value as u64)
    }
}

impl From<f32> for Value {
    fn from(value: f32) -> Self {
        Self::F64(f64::from(value))
    }
}

impl From<f64> for Value {
    fn from(value: f64) -> Self {
        Self::F64(value)
    }
}

impl From<&str> for Value {
    fn from(value: &str) -> Self {
        Self::Text(value.to_string())
    }
}

impl From<String> for Value {
    fn from(value: String) -> Self {
        Self::Text(value)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Field {
    pub key: String,
    pub value: Value,
}

impl Field {
    pub fn new(key: impl Into<String>, value: impl Into<Value>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Phase {
    pub name: String,
    pub duration_us: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct EventRecord {
    pub seq: u64,
    pub uptime_us: u64,
    pub unix_ms: u64,
    pub thread: String,
    pub category: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_us: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<Field>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct FrameRecord {
    pub seq: u64,
    pub frame: u64,
    pub uptime_us: u64,
    pub unix_ms: u64,
    pub budget_us: u64,
    pub total_us: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_wait_us: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_wait_us: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_interval_us: Option<u64>,
    pub missed: Vec<String>,
    pub phases: Vec<Phase>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<Field>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "record", rename_all = "snake_case")]
pub enum Record {
    Event(EventRecord),
    Frame(FrameRecord),
}

impl Record {
    pub fn seq(&self) -> u64 {
        match self {
            Self::Event(event) => event.seq,
            Self::Frame(frame) => frame.seq,
        }
    }

    pub fn uptime_us(&self) -> u64 {
        match self {
            Self::Event(event) => event.uptime_us,
            Self::Frame(frame) => frame.uptime_us,
        }
    }

    pub fn duration_us(&self) -> u64 {
        match self {
            Self::Event(event) => event.duration_us.unwrap_or(0),
            Self::Frame(frame) => frame.total_us,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct FrameSummary {
    pub frames: u64,
    pub dropped_frames: u64,
    pub total_us: u64,
    pub max_us: u64,
    pub max_request_wait_us: u64,
    pub max_input_wait_us: u64,
    pub max_active_interval_us: u64,
    pub buckets: [u64; 9],
}

impl FrameSummary {
    pub fn record(
        &mut self,
        total_us: u64,
        request_wait_us: Option<u64>,
        input_wait_us: Option<u64>,
        active_interval_us: Option<u64>,
        dropped: bool,
    ) {
        self.frames = self.frames.saturating_add(1);
        self.dropped_frames = self.dropped_frames.saturating_add(u64::from(dropped));
        self.total_us = self.total_us.saturating_add(total_us);
        self.max_us = self.max_us.max(total_us);
        self.max_request_wait_us = self.max_request_wait_us.max(request_wait_us.unwrap_or(0));
        self.max_input_wait_us = self.max_input_wait_us.max(input_wait_us.unwrap_or(0));
        self.max_active_interval_us = self
            .max_active_interval_us
            .max(active_interval_us.unwrap_or(0));
        let index = match total_us {
            0..=8_000 => 0,
            8_001..=16_667 => 1,
            16_668..=20_000 => 2,
            20_001..=25_000 => 3,
            25_001..=33_334 => 4,
            33_335..=50_000 => 5,
            50_001..=100_000 => 6,
            100_001..=250_000 => 7,
            _ => 8,
        };
        self.buckets[index] = self.buckets[index].saturating_add(1);
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct BusyState {
    pub episode: u64,
    pub since_unix_ms: u64,
    pub last_progress_unix_ms: u64,
    pub activity: String,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct ProcessSample {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rss_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_user: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_kernel: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_token: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Snapshot {
    pub unix_ms: u64,
    pub uptime_ms: u64,
    #[serde(default = "default_frame_budget_us")]
    pub frame_budget_us: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub busy: Option<BusyState>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub state: Vec<Field>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub records: Vec<Record>,
    pub frame_summary: FrameSummary,
    pub recorder_dropped: u64,
}

fn default_frame_budget_us() -> u64 {
    16_667
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "message", rename_all = "snake_case")]
pub enum WatchMessage {
    Snapshot(Snapshot),
    Clean { unix_ms: u64 },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Attachment {
    pub name: String,
    pub media_type: String,
    pub bytes: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Report {
    pub schema: u32,
    pub report_id: String,
    pub topic: String,
    pub kind: String,
    pub app: String,
    pub version: String,
    pub device: String,
    pub run_id: String,
    pub pid: u32,
    pub unix_ms: u64,
    pub uptime_ms: u64,
    pub os: String,
    pub arch: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessSample>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub state: Vec<Field>,
    pub frame_summary: FrameSummary,
    pub recorder_dropped: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub records: Vec<Record>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<Field>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<Attachment>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct WatchdogLaunch {
    pub app: String,
    pub version: String,
    pub device: String,
    pub run_id: String,
    pub parent_pid: u32,
    pub parent_start_token: Option<u64>,
    pub start_unix_ms: u64,
    pub data_dir: std::path::PathBuf,
    pub endpoint: Option<String>,
    pub native_dump_path: std::path::PathBuf,
    pub ring_capacity: usize,
    pub spool_max_bytes: u64,
    pub stall_ms: u64,
    pub hang_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct RunCheckpoint {
    pub launch: WatchdogLaunch,
    pub snapshot: Snapshot,
    pub records: Vec<Record>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct SpoolEnvelope {
    pub report: Report,
    pub attachment_paths: Vec<std::path::PathBuf>,
}

pub fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

pub(crate) fn unique_id(prefix: &str) -> String {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!(
        "{prefix}-{:x}-{:x}-{:x}",
        unix_ms(),
        std::process::id(),
        sequence
    )
}
