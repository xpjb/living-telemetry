use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::protocol::{Attachment, Report, SpoolEnvelope};
use crate::transport::Endpoint;

pub(crate) struct Spool {
    root: PathBuf,
    max_bytes: u64,
    endpoint: Option<Endpoint>,
    usage: Mutex<HashMap<PathBuf, CachedUsage>>,
}

#[derive(Clone)]
struct CachedUsage {
    json_bytes: u64,
    priority: u8,
    attachments: Vec<PathBuf>,
}

// Recovery needs only this index, not thousands of allocated frame records.
#[derive(serde::Deserialize)]
struct EnvelopeIndex {
    report: ReportIndex,
    attachment_paths: Vec<PathBuf>,
}
#[derive(serde::Deserialize)]
struct ReportIndex {
    kind: String,
}

impl Spool {
    pub fn new(root: PathBuf, max_bytes: u64, endpoint: Option<&str>) -> Result<Self, String> {
        fs::create_dir_all(&root).map_err(|err| format!("create telemetry spool: {err}"))?;
        let endpoint = endpoint.map(Endpoint::parse).transpose()?;
        Ok(Self {
            root,
            max_bytes,
            endpoint,
            usage: Mutex::new(HashMap::new()),
        })
    }

    pub fn enqueue(
        &self,
        mut report: Report,
        attachments: Vec<PathBuf>,
    ) -> Result<PathBuf, String> {
        report.attachments = attachments
            .iter()
            .filter_map(|path| {
                let metadata = fs::metadata(path).ok()?;
                Some(Attachment {
                    name: path.file_name()?.to_string_lossy().into_owned(),
                    media_type: attachment_media_type(path).to_string(),
                    bytes: metadata.len(),
                })
            })
            .collect();
        let envelope = SpoolEnvelope {
            report,
            attachment_paths: attachments,
        };
        let priority = report_priority(&envelope.report.kind);
        let filename = format!(
            "{priority}-{}-{}.json",
            envelope.report.unix_ms, envelope.report.report_id
        );
        let path = self.root.join(filename);
        atomic_json(&path, &envelope)?;
        self.usage.lock().unwrap_or_else(|p| p.into_inner()).insert(
            path.clone(),
            CachedUsage {
                json_bytes: fs::metadata(&path).map(|m| m.len()).unwrap_or(0),
                priority,
                attachments: envelope.attachment_paths,
            },
        );
        self.enforce_bound();
        Ok(path)
    }

    pub fn flush(&self) {
        let Some(endpoint) = &self.endpoint else {
            return;
        };
        let Ok(entries) = spool_entries(&self.root) else {
            return;
        };
        for path in entries {
            let Ok(bytes) = fs::read(&path) else {
                continue;
            };
            let Ok(envelope) = serde_json::from_slice::<SpoolEnvelope>(&bytes) else {
                let _ = quarantine(&path);
                continue;
            };
            let Ok(report_body) = serde_json::to_vec(&envelope.report) else {
                continue;
            };
            if endpoint.post_report(&report_body).is_err() {
                break;
            }
            let mut attachments_ok = true;
            for attachment in &envelope.attachment_paths {
                let Ok(body) = fs::read(attachment) else {
                    continue;
                };
                let name = attachment
                    .file_name()
                    .and_then(|value| value.to_str())
                    .unwrap_or("attachment.bin");
                let headers = [
                    ("X-Telemetry-Topic", envelope.report.topic.as_str()),
                    ("X-Telemetry-App", envelope.report.app.as_str()),
                    ("X-Telemetry-Device", envelope.report.device.as_str()),
                    ("X-Telemetry-Report", envelope.report.report_id.as_str()),
                    ("X-Telemetry-Name", name),
                ];
                if endpoint.post_attachment(&headers, &body).is_err() {
                    attachments_ok = false;
                    break;
                }
            }
            if !attachments_ok {
                break;
            }
            for attachment in envelope.attachment_paths {
                let _ = fs::remove_file(attachment);
            }
            let _ = fs::remove_file(path);
        }
    }

    fn enforce_bound(&self) {
        let Ok(entries) = spool_entries(&self.root) else {
            return;
        };
        let mut usage = self.usage.lock().unwrap_or_else(|p| p.into_inner());
        // Spool envelopes are immutable after atomic publication. Cache only
        // their small accounting index; never re-read/deserialize the whole
        // offline backlog on every enqueue. The uploader may delete entries.
        usage.retain(|path, _| entries.binary_search(path).is_ok());
        let mut sized = entries
            .into_iter()
            .filter_map(|path| {
                let json_bytes = fs::metadata(&path).ok()?.len();
                if usage
                    .get(&path)
                    .is_none_or(|entry| entry.json_bytes != json_bytes)
                {
                    let index = fs::read(&path)
                        .ok()
                        .and_then(|bytes| serde_json::from_slice::<EnvelopeIndex>(&bytes).ok());
                    usage.insert(
                        path.clone(),
                        CachedUsage {
                            json_bytes,
                            priority: index
                                .as_ref()
                                .map_or(5, |index| report_priority(&index.report.kind)),
                            attachments: index
                                .map_or_else(Vec::new, |index| index.attachment_paths),
                        },
                    );
                }
                let entry = usage.get(&path).unwrap().clone();
                let attachments = entry
                    .attachments
                    .iter()
                    .filter_map(|path| fs::metadata(path).ok().map(|m| m.len()))
                    .sum::<u64>();
                Some((path, json_bytes.saturating_add(attachments), entry))
            })
            .collect::<Vec<_>>();
        let mut total = sized.iter().map(|(_, bytes, _)| *bytes).sum::<u64>();
        if total <= self.max_bytes {
            return;
        }
        sized.sort_by(|left, right| {
            right
                .2
                .priority
                .cmp(&left.2.priority)
                .then_with(|| left.0.cmp(&right.0))
        });
        for (path, bytes, entry) in sized {
            if total <= self.max_bytes {
                break;
            }
            for attachment in entry.attachments {
                let _ = fs::remove_file(attachment);
            }
            if fs::remove_file(&path).is_ok() {
                usage.remove(&path);
                total = total.saturating_sub(bytes);
            }
        }
    }
}

fn report_priority(kind: &str) -> u8 {
    match kind {
        "panic" | "native_crash" | "process_exit" | "previous_unclean_exit"
        | "watchdog_channel_closed" => 0,
        "hang" | "hang_continues" => 1,
        "stall" | "stall_recovered" => 2,
        "frame_drops" | "slow_intervals" => 3,
        _ => 4,
    }
}

fn attachment_media_type(path: &Path) -> &'static str {
    match path.extension().and_then(|value| value.to_str()) {
        Some("dmp") => "application/x-minidump",
        _ => "application/octet-stream",
    }
}

fn spool_entries(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut entries = fs::read_dir(root)
        .map_err(|err| err.to_string())?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect::<Vec<_>>();
    entries.sort();
    Ok(entries)
}

pub(crate) fn atomic_json(path: &Path, value: &impl serde::Serialize) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "telemetry path has no parent".to_string())?;
    fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    let temp = path.with_extension(format!(
        "tmp-{}-{}",
        std::process::id(),
        crate::protocol::unix_ms()
    ));
    let bytes = serde_json::to_vec(value).map_err(|err| err.to_string())?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp)
        .map_err(|err| err.to_string())?;
    file.write_all(&bytes).map_err(|err| err.to_string())?;
    file.flush().map_err(|err| err.to_string())?;
    drop(file);
    fs::rename(&temp, path).map_err(|err| {
        let _ = fs::remove_file(&temp);
        err.to_string()
    })
}

fn quarantine(path: &Path) -> Result<(), String> {
    fs::rename(path, path.with_extension("invalid")).map_err(|err| err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{FrameSummary, SCHEMA_VERSION, unique_id, unix_ms};

    fn temp_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(unique_id(name))
    }

    fn report(kind: &str) -> Report {
        Report {
            schema: SCHEMA_VERSION,
            report_id: unique_id("report"),
            topic: "performance".to_string(),
            kind: kind.to_string(),
            app: "test".to_string(),
            version: "1".to_string(),
            device: "device".to_string(),
            run_id: "run".to_string(),
            pid: 1,
            unix_ms: unix_ms(),
            uptime_ms: 0,
            os: "test".to_string(),
            arch: "test".to_string(),
            process: None,
            state: Vec::new(),
            frame_summary: FrameSummary::default(),
            recorder_dropped: 0,
            records: Vec::new(),
            fields: Vec::new(),
            attachments: Vec::new(),
        }
    }

    #[test]
    fn spool_bound_discards_summaries_before_crashes() {
        let root = temp_dir("living-telemetry-spool");
        let spool = Spool::new(root.clone(), u64::MAX, None).unwrap();
        spool.enqueue(report("runtime_summary"), Vec::new()).unwrap();
        let crash = spool.enqueue(report("process_exit"), Vec::new()).unwrap();
        let crash_bytes = fs::metadata(crash).unwrap().len();
        let bounded = Spool::new(root.clone(), crash_bytes, None).unwrap();
        bounded.enforce_bound();
        let entries = spool_entries(&root).unwrap();
        assert_eq!(entries.len(), 1);
        let envelope: SpoolEnvelope =
            serde_json::from_slice(&fs::read(&entries[0]).unwrap()).unwrap();
        assert_eq!(envelope.report.kind, "process_exit");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cached_budget_includes_attachments_and_prunes_uploaded_entries() {
        let root = temp_dir("living-telemetry-cached-budget");
        let spool = Spool::new(root.clone(), u64::MAX, None).unwrap();
        let dump = root.join("hang.dmp");
        fs::write(&dump, vec![0u8; 4096]).unwrap();
        let hang = spool.enqueue(report("hang"), vec![dump.clone()]).unwrap();
        let summary = spool
            .enqueue(report("runtime_summary"), Vec::new())
            .unwrap();
        assert_eq!(spool.usage.lock().unwrap().len(), 2);
        // A new process recovers only the lightweight kind/attachment index.
        let budget = fs::metadata(&hang).unwrap().len() + 4096;
        let bounded = Spool::new(root.clone(), budget, None).unwrap();
        bounded.enforce_bound();
        assert!(hang.exists() && dump.exists());
        assert!(!summary.exists());
        assert_eq!(bounded.usage.lock().unwrap().len(), 1);
        fs::remove_file(&hang).unwrap(); // Model a successful upload.
        fs::remove_file(&dump).unwrap();
        bounded.enforce_bound();
        assert!(bounded.usage.lock().unwrap().is_empty());
        let _ = fs::remove_dir_all(root);
    }
}
