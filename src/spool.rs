use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::protocol::{Attachment, Report, SpoolEnvelope};
use crate::transport::Endpoint;

pub(crate) struct Spool {
    root: PathBuf,
    max_bytes: u64,
    endpoint: Option<Endpoint>,
}

impl Spool {
    pub fn new(root: PathBuf, max_bytes: u64, endpoint: Option<&str>) -> Result<Self, String> {
        fs::create_dir_all(&root).map_err(|err| format!("create telemetry spool: {err}"))?;
        let endpoint = endpoint.map(Endpoint::parse).transpose()?;
        Ok(Self {
            root,
            max_bytes,
            endpoint,
        })
    }

    pub fn enqueue(&self, mut report: Report, attachments: Vec<PathBuf>) -> Result<PathBuf, String> {
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
        let mut sized = entries
            .into_iter()
            .filter_map(|path| {
                let metadata = fs::metadata(&path).ok()?;
                let envelope = fs::read(&path)
                    .ok()
                    .and_then(|bytes| serde_json::from_slice::<SpoolEnvelope>(&bytes).ok());
                let attachments = envelope
                    .as_ref()
                    .map(|envelope| {
                        envelope
                            .attachment_paths
                            .iter()
                            .filter_map(|path| fs::metadata(path).ok().map(|meta| meta.len()))
                            .sum::<u64>()
                    })
                    .unwrap_or(0);
                Some((path, metadata.len().saturating_add(attachments), envelope))
            })
            .collect::<Vec<_>>();
        let mut total = sized.iter().map(|(_, bytes, _)| *bytes).sum::<u64>();
        if total <= self.max_bytes {
            return;
        }
        sized.sort_by(|left, right| {
            deletion_rank(&left.2)
                .cmp(&deletion_rank(&right.2))
                .reverse()
                .then_with(|| left.0.cmp(&right.0))
        });
        for (path, bytes, envelope) in sized {
            if total <= self.max_bytes {
                break;
            }
            if let Some(envelope) = envelope {
                for attachment in envelope.attachment_paths {
                    let _ = fs::remove_file(attachment);
                }
            }
            if fs::remove_file(path).is_ok() {
                total = total.saturating_sub(bytes);
            }
        }
    }
}

fn report_priority(kind: &str) -> u8 {
    match kind {
        "panic" | "native_crash" | "process_exit" | "previous_unclean_exit" => 0,
        "hang" | "hang_continues" => 1,
        "stall" | "stall_recovered" => 2,
        "frame_drops" | "slow_intervals" => 3,
        _ => 4,
    }
}

fn deletion_rank(envelope: &Option<SpoolEnvelope>) -> u8 {
    envelope
        .as_ref()
        .map(|envelope| report_priority(&envelope.report.kind))
        .unwrap_or(5)
}

fn attachment_media_type(path: &Path) -> &'static str {
    match path.extension().and_then(|value| value.to_str()) {
        Some("dmp") => "application/vnd.microsoft.portable-executable",
        _ => "application/octet-stream",
    }
}

fn spool_entries(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut entries = fs::read_dir(root)
        .map_err(|err| err.to_string())?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "json"))
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
}
