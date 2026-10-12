use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;

use crate::protocol::{Report, unix_ms};

pub struct CollectorConfig {
    pub bind: SocketAddr,
    pub root: PathBuf,
    pub allow_public_bind: bool,
    pub max_report_bytes: usize,
    pub max_attachment_bytes: usize,
}

impl CollectorConfig {
    pub fn new(bind: SocketAddr, root: impl Into<PathBuf>) -> Self {
        Self {
            bind,
            root: root.into(),
            allow_public_bind: false,
            max_report_bytes: 32 * 1024 * 1024,
            max_attachment_bytes: 128 * 1024 * 1024,
        }
    }
}

pub fn run(config: CollectorConfig) -> Result<(), String> {
    validate_bind(config.bind.ip(), config.allow_public_bind)?;
    fs::create_dir_all(&config.root).map_err(|err| err.to_string())?;
    let listener = TcpListener::bind(config.bind)
        .map_err(|err| format!("bind telemetry collector {}: {err}", config.bind))?;
    serve(listener, &config, None)
}

fn serve(
    listener: TcpListener,
    config: &CollectorConfig,
    limit: Option<usize>,
) -> Result<(), String> {
    let mut served = 0usize;
    for connection in listener.incoming() {
        let mut stream = match connection {
            Ok(stream) => stream,
            Err(err) => return Err(err.to_string()),
        };
        let peer = stream.peer_addr().ok();
        let result = if peer.is_some_and(|peer| !tailnet_or_loopback(peer.ip())) {
            write_response(&mut stream, 403, "text/plain", b"tailnet only\n")
        } else {
            handle_connection(&mut stream, peer, config)
        };
        if result.is_err() {
            let _ = write_response(&mut stream, 500, "text/plain", b"collector error\n");
        }
        served += 1;
        if limit.is_some_and(|limit| served >= limit) {
            break;
        }
    }
    Ok(())
}

fn handle_connection(
    stream: &mut TcpStream,
    peer: Option<SocketAddr>,
    config: &CollectorConfig,
) -> Result<(), String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|err| err.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|err| err.to_string())?;
    let request = read_request(stream, config)?;
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/health") => write_response(stream, 200, "text/plain", b"ok\n"),
        ("POST", "/v1/report") => {
            let report = serde_json::from_slice::<Report>(&request.body)
                .map_err(|err| format!("decode telemetry report: {err}"))?;
            let relative = store_report(&config.root, &report, &request.body)?;
            append_index(
                &config.root,
                &IndexEntry {
                    received_unix_ms: unix_ms(),
                    peer: peer.map(|peer| peer.to_string()),
                    topic: report.topic,
                    kind: report.kind,
                    app: report.app,
                    device: report.device,
                    report_id: report.report_id,
                    path: relative.to_string_lossy().into_owned(),
                },
            )?;
            write_response(stream, 202, "application/json", b"{\"ok\":true}\n")
        }
        ("POST", "/v1/attachment") => {
            let topic = request.header("x-telemetry-topic").unwrap_or("attachment");
            let app = request.header("x-telemetry-app").unwrap_or("unknown");
            let device = request.header("x-telemetry-device").unwrap_or("unknown");
            let report = request.header("x-telemetry-report").unwrap_or("unknown");
            let name = request.header("x-telemetry-name").unwrap_or("attachment.bin");
            let relative = PathBuf::from(sanitize(topic))
                .join(sanitize(app))
                .join(sanitize(device))
                .join(format!("{}-{}", sanitize(report), sanitize(name)));
            atomic_bytes(&config.root.join(&relative), &request.body)?;
            append_index(
                &config.root,
                &IndexEntry {
                    received_unix_ms: unix_ms(),
                    peer: peer.map(|peer| peer.to_string()),
                    topic: topic.to_string(),
                    kind: "attachment".to_string(),
                    app: app.to_string(),
                    device: device.to_string(),
                    report_id: report.to_string(),
                    path: relative.to_string_lossy().into_owned(),
                },
            )?;
            write_response(stream, 202, "application/json", b"{\"ok\":true}\n")
        }
        _ => write_response(stream, 404, "text/plain", b"not found\n"),
    }
}

struct Request {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find_map(|(key, value)| (key == name).then_some(value.as_str()))
    }
}

fn read_request(stream: &mut TcpStream, config: &CollectorConfig) -> Result<Request, String> {
    const HEADER_LIMIT: usize = 16 * 1024;
    let mut bytes = Vec::with_capacity(4096);
    let mut buffer = [0u8; 4096];
    let header_end = loop {
        let count = stream.read(&mut buffer).map_err(|err| err.to_string())?;
        if count == 0 {
            return Err("connection closed before HTTP headers".to_string());
        }
        bytes.extend_from_slice(&buffer[..count]);
        if let Some(index) = find_header_end(&bytes) {
            break index;
        }
        if bytes.len() > HEADER_LIMIT {
            return Err("telemetry HTTP headers are too large".to_string());
        }
    };
    let header = std::str::from_utf8(&bytes[..header_end])
        .map_err(|_| "telemetry HTTP headers are not UTF-8".to_string())?;
    let mut lines = header.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| "missing HTTP request line".to_string())?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().unwrap_or_default().to_string();
    let path = request_parts.next().unwrap_or_default().to_string();
    if request_parts.next().is_none() {
        return Err("invalid HTTP request line".to_string());
    }
    let headers = lines
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            Some((key.trim().to_ascii_lowercase(), value.trim().to_string()))
        })
        .collect::<Vec<_>>();
    let content_length = headers
        .iter()
        .find_map(|(key, value)| (key == "content-length").then_some(value))
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|_| "invalid Content-Length".to_string())
        })
        .transpose()?
        .unwrap_or(0);
    let limit = if path == "/v1/attachment" {
        config.max_attachment_bytes
    } else {
        config.max_report_bytes
    };
    if content_length > limit {
        return Err(format!("telemetry request exceeds {limit} bytes"));
    }
    let body_start = header_end + 4;
    let mut body = bytes[body_start.min(bytes.len())..].to_vec();
    while body.len() < content_length {
        let count = stream.read(&mut buffer).map_err(|err| err.to_string())?;
        if count == 0 {
            return Err("connection closed before HTTP body".to_string());
        }
        let remaining = content_length - body.len();
        body.extend_from_slice(&buffer[..count.min(remaining)]);
    }
    body.truncate(content_length);
    Ok(Request {
        method,
        path,
        headers,
        body,
    })
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn store_report(root: &Path, report: &Report, body: &[u8]) -> Result<PathBuf, String> {
    let relative = PathBuf::from(sanitize(&report.topic))
        .join(sanitize(&report.app))
        .join(sanitize(&report.device))
        .join(format!(
            "{}-{}.json",
            report.unix_ms,
            sanitize(&report.report_id)
        ));
    atomic_bytes(&root.join(&relative), body)?;
    Ok(relative)
}

fn atomic_bytes(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "collector path has no parent".to_string())?;
    fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    let temp = path.with_extension(format!("tmp-{}", std::process::id()));
    fs::write(&temp, bytes).map_err(|err| err.to_string())?;
    fs::rename(&temp, path).map_err(|err| {
        let _ = fs::remove_file(&temp);
        err.to_string()
    })
}

#[derive(Serialize)]
struct IndexEntry {
    received_unix_ms: u64,
    peer: Option<String>,
    topic: String,
    kind: String,
    app: String,
    device: String,
    report_id: String,
    path: String,
}

fn append_index(root: &Path, entry: &IndexEntry) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(root.join("index.jsonl"))
        .map_err(|err| err.to_string())?;
    serde_json::to_writer(&mut file, entry).map_err(|err| err.to_string())?;
    file.write_all(b"\n").map_err(|err| err.to_string())
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<(), String> {
    let reason = match status {
        200 => "OK",
        202 => "Accepted",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "Internal Server Error",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .map_err(|err| err.to_string())?;
    stream.write_all(body).map_err(|err| err.to_string())?;
    stream.flush().map_err(|err| err.to_string())
}

pub fn validate_bind(ip: IpAddr, allow_public: bool) -> Result<(), String> {
    if allow_public || tailnet_or_loopback(ip) {
        Ok(())
    } else {
        Err(format!(
            "refusing non-loopback, non-Tailscale collector bind {ip}; pass --allow-public-bind to override"
        ))
    }
}

pub fn tailnet_or_loopback(ip: IpAddr) -> bool {
    if ip.is_loopback() {
        return true;
    }
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            octets[0] == 100 && (64..=127).contains(&octets[1])
        }
        IpAddr::V6(ip) => ip.octets()[..6] == [0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0],
    }
}

fn sanitize(value: &str) -> String {
    let value = value
        .chars()
        .take(80)
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    if value.is_empty() || value == "." || value == ".." {
        "unknown".to_string()
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{FrameSummary, SCHEMA_VERSION, unique_id};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::thread;

    fn report() -> Report {
        Report {
            schema: SCHEMA_VERSION,
            report_id: unique_id("report"),
            topic: "performance".to_string(),
            kind: "frame_drops".to_string(),
            app: "test/app".to_string(),
            version: "1".to_string(),
            device: "device".to_string(),
            run_id: "run".to_string(),
            pid: 1,
            unix_ms: unix_ms(),
            uptime_ms: 1,
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
    fn bind_guard_accepts_tailnet_and_loopback_only() {
        assert!(tailnet_or_loopback(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(tailnet_or_loopback(IpAddr::V4(Ipv4Addr::new(100, 91, 37, 121))));
        assert!(tailnet_or_loopback(IpAddr::V6(Ipv6Addr::new(
            0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 1
        ))));
        assert!(!tailnet_or_loopback(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))));
        assert!(!tailnet_or_loopback(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))));
    }

    #[test]
    fn report_round_trip_stores_topic_tree() {
        let root = std::env::temp_dir().join(unique_id("living-telemetry-collector"));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let config = CollectorConfig::new(address, root.clone());
        let server = thread::spawn(move || serve(listener, &config, Some(1)).unwrap());
        let report = report();
        let endpoint = crate::transport::Endpoint::parse(&format!(
            "http://{address}/v1/report"
        ))
        .unwrap();
        endpoint
            .post_report(&serde_json::to_vec(&report).unwrap())
            .unwrap();
        server.join().unwrap();
        let expected = root
            .join("performance")
            .join("test_app")
            .join("device")
            .join(format!("{}-{}.json", report.unix_ms, report.report_id));
        assert!(expected.exists());
        assert!(root.join("index.jsonl").exists());
        let _ = fs::remove_dir_all(root);
    }
}
