use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Endpoint {
    pub host: String,
    pub port: u16,
    pub report_path: String,
}

impl Endpoint {
    pub fn parse(value: &str) -> Result<Self, String> {
        let rest = value
            .strip_prefix("http://")
            .ok_or_else(|| "telemetry endpoint must use http://".to_string())?;
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        if authority.is_empty() {
            return Err("telemetry endpoint has no host".to_string());
        }
        let report_path = format!("/{}", path.trim_start_matches('/'));
        let report_path = if report_path == "/" {
            "/v1/report".to_string()
        } else {
            report_path
        };
        let (host, port) = parse_authority(authority)?;
        Ok(Self {
            host,
            port,
            report_path,
        })
    }

    pub fn attachment_path(&self) -> String {
        self.report_path
            .strip_suffix("/report")
            .map(|prefix| format!("{prefix}/attachment"))
            .unwrap_or_else(|| "/v1/attachment".to_string())
    }

    pub fn post_report(&self, body: &[u8]) -> Result<(), String> {
        self.post(
            &self.report_path,
            "application/json",
            &[],
            body,
        )
    }

    pub fn post_attachment(
        &self,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<(), String> {
        self.post(
            &self.attachment_path(),
            "application/octet-stream",
            headers,
            body,
        )
    }

    fn post(
        &self,
        path: &str,
        content_type: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<(), String> {
        let addresses = (self.host.as_str(), self.port)
            .to_socket_addrs()
            .map_err(|err| format!("resolve {}:{}: {err}", self.host, self.port))?
            .collect::<Vec<_>>();
        if addresses.is_empty() {
            return Err(format!("no address for {}:{}", self.host, self.port));
        }
        let mut last_error = None;
        for address in addresses {
            match self.post_to(address, path, content_type, headers, body) {
                Ok(()) => return Ok(()),
                Err(err) => last_error = Some(err),
            }
        }
        Err(last_error.unwrap_or_else(|| "telemetry connection failed".to_string()))
    }

    fn post_to(
        &self,
        address: SocketAddr,
        path: &str,
        content_type: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<(), String> {
        let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))
            .map_err(|err| format!("connect {address}: {err}"))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|err| err.to_string())?;
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .map_err(|err| err.to_string())?;
        write!(
            stream,
            "POST {path} HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: living-telemetry/{}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n",
            self.host,
            self.port,
            env!("CARGO_PKG_VERSION"),
            body.len(),
        )
        .map_err(|err| err.to_string())?;
        for (name, value) in headers {
            if !header_token(name) || value.contains(['\r', '\n']) {
                return Err("invalid telemetry attachment header".to_string());
            }
            write!(stream, "{name}: {value}\r\n").map_err(|err| err.to_string())?;
        }
        stream.write_all(b"\r\n").map_err(|err| err.to_string())?;
        stream.write_all(body).map_err(|err| err.to_string())?;
        stream.flush().map_err(|err| err.to_string())?;

        let mut response = Vec::with_capacity(512);
        let mut chunk = [0u8; 128];
        while response.len() < 512 && !response.windows(2).any(|window| window == b"\r\n") {
            let count = stream.read(&mut chunk).map_err(|err| err.to_string())?;
            if count == 0 {
                break;
            }
            response.extend_from_slice(&chunk[..count]);
        }
        let line = std::str::from_utf8(&response)
            .ok()
            .and_then(|response| response.lines().next())
            .ok_or_else(|| "invalid telemetry HTTP response".to_string())?;
        let status = line
            .split_whitespace()
            .nth(1)
            .and_then(|value| value.parse::<u16>().ok())
            .ok_or_else(|| format!("invalid telemetry HTTP status: {line}"))?;
        if (200..300).contains(&status) {
            Ok(())
        } else {
            Err(format!("telemetry HTTP {status}"))
        }
    }
}

fn parse_authority(authority: &str) -> Result<(String, u16), String> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, port) = rest
            .split_once("]:")
            .ok_or_else(|| "IPv6 telemetry endpoint must include a port".to_string())?;
        let port = port
            .parse::<u16>()
            .map_err(|_| "invalid telemetry endpoint port".to_string())?;
        return Ok((host.to_string(), port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => Ok((
            host.to_string(),
            port.parse::<u16>()
                .map_err(|_| "invalid telemetry endpoint port".to_string())?,
        )),
        _ => Ok((authority.to_string(), 80)),
    }
}

fn header_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'!' | b'#'..=b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_report_and_attachment_paths() {
        let endpoint = Endpoint::parse("http://vibe.test:4318/v1/report").unwrap();
        assert_eq!(endpoint.host, "vibe.test");
        assert_eq!(endpoint.port, 4318);
        assert_eq!(endpoint.report_path, "/v1/report");
        assert_eq!(endpoint.attachment_path(), "/v1/attachment");
    }

    #[test]
    fn rejects_tls_and_bad_ports() {
        assert!(Endpoint::parse("https://vibe.test/v1/report").is_err());
        assert!(Endpoint::parse("http://vibe.test:nope/v1/report").is_err());
    }
}
