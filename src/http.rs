use anyhow::{anyhow, bail, Context, Result};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use crate::target::{parse_host_port, Target};

pub(crate) const MAX_HTTP_HEADER: usize = 64 * 1024;

pub(crate) async fn read_http_target(stream: &mut TcpStream) -> Result<(Target, Vec<u8>)> {
    let header = read_until_header_end(stream).await?;
    let target = parse_http_host(&header)?;
    Ok((target, header))
}

pub(crate) async fn read_until_header_end(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 1024];

    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            bail!("connection closed before HTTP header");
        }
        buf.extend_from_slice(&chunk[..n]);
        if header_end(&buf).is_some() {
            return Ok(buf);
        }
        if buf.len() > MAX_HTTP_HEADER {
            bail!("HTTP header exceeds {} bytes", MAX_HTTP_HEADER);
        }
    }
}

pub(crate) fn header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

pub(crate) fn parse_http_host(header: &[u8]) -> Result<Target> {
    let end = header_end(header).ok_or_else(|| anyhow!("incomplete HTTP header"))?;
    let text = std::str::from_utf8(&header[..end]).context("HTTP header is not valid UTF-8")?;

    for line in text.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("host") {
            return parse_host_port(value.trim(), 80);
        }
    }

    bail!("HTTP Host header not found");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_http_host() {
        let target = parse_http_host(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").unwrap();
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, 80);
    }

    #[test]
    fn parses_http_host_with_port_and_case() {
        let target =
            parse_http_host(b"GET / HTTP/1.1\r\nhOsT: example.com:8080\r\n\r\nbody").unwrap();
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, 8080);
    }

    #[test]
    fn rejects_missing_http_host() {
        assert!(parse_http_host(b"GET / HTTP/1.1\r\n\r\n").is_err());
    }
}
