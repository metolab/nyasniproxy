use anyhow::{bail, Result};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use crate::target::Target;

const MAX_CLIENT_HELLO: usize = 64 * 1024;

pub(crate) async fn read_https_target(stream: &mut TcpStream) -> Result<(Target, Vec<u8>)> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 1024];

    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            bail!("connection closed before TLS ClientHello");
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_CLIENT_HELLO {
            bail!("TLS ClientHello exceeds {} bytes", MAX_CLIENT_HELLO);
        }
        match parse_tls_sni(&buf) {
            ClientHelloStatus::NeedMore => continue,
            ClientHelloStatus::Found(host) => {
                return Ok((Target { host, port: 443 }, buf));
            }
            ClientHelloStatus::Invalid(reason) => bail!("{reason}"),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ClientHelloStatus {
    NeedMore,
    Found(String),
    Invalid(String),
}

pub(crate) fn parse_tls_sni(buf: &[u8]) -> ClientHelloStatus {
    if buf.len() < 5 {
        return ClientHelloStatus::NeedMore;
    }
    if buf[0] != 22 {
        return ClientHelloStatus::Invalid("not a TLS handshake record".to_string());
    }

    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let record_end = 5 + record_len;
    if buf.len() < record_end {
        return ClientHelloStatus::NeedMore;
    }

    let record = &buf[5..record_end];
    if record.len() < 4 || record[0] != 1 {
        return ClientHelloStatus::Invalid("not a TLS ClientHello".to_string());
    }
    let hello_len = ((record[1] as usize) << 16) | ((record[2] as usize) << 8) | record[3] as usize;
    if record.len() < 4 + hello_len {
        return ClientHelloStatus::NeedMore;
    }

    parse_client_hello_body(&record[4..4 + hello_len])
}

fn parse_client_hello_body(mut body: &[u8]) -> ClientHelloStatus {
    if body.len() < 34 {
        return ClientHelloStatus::Invalid("truncated ClientHello".to_string());
    }
    body = &body[34..];

    let Some((&session_id_len, rest)) = body.split_first() else {
        return ClientHelloStatus::Invalid("missing session id length".to_string());
    };
    if rest.len() < session_id_len as usize {
        return ClientHelloStatus::Invalid("truncated session id".to_string());
    }
    body = &rest[session_id_len as usize..];

    if body.len() < 2 {
        return ClientHelloStatus::Invalid("missing cipher suites length".to_string());
    }
    let cipher_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    if body.len() < 2 + cipher_len {
        return ClientHelloStatus::Invalid("truncated cipher suites".to_string());
    }
    body = &body[2 + cipher_len..];

    let Some((&compression_len, rest)) = body.split_first() else {
        return ClientHelloStatus::Invalid("missing compression methods length".to_string());
    };
    if rest.len() < compression_len as usize {
        return ClientHelloStatus::Invalid("truncated compression methods".to_string());
    }
    body = &rest[compression_len as usize..];

    if body.len() < 2 {
        return ClientHelloStatus::Invalid("missing extensions length".to_string());
    }
    let extensions_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    if body.len() < 2 + extensions_len {
        return ClientHelloStatus::Invalid("truncated extensions".to_string());
    }

    let mut extensions = &body[2..2 + extensions_len];
    while !extensions.is_empty() {
        if extensions.len() < 4 {
            return ClientHelloStatus::Invalid("truncated extension header".to_string());
        }
        let ext_type = u16::from_be_bytes([extensions[0], extensions[1]]);
        let ext_len = u16::from_be_bytes([extensions[2], extensions[3]]) as usize;
        if extensions.len() < 4 + ext_len {
            return ClientHelloStatus::Invalid("truncated extension".to_string());
        }
        let ext_data = &extensions[4..4 + ext_len];
        if ext_type == 0 {
            return parse_sni_extension(ext_data);
        }
        extensions = &extensions[4 + ext_len..];
    }

    ClientHelloStatus::Invalid("TLS SNI extension not found".to_string())
}

fn parse_sni_extension(data: &[u8]) -> ClientHelloStatus {
    if data.len() < 2 {
        return ClientHelloStatus::Invalid("truncated SNI extension".to_string());
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + list_len {
        return ClientHelloStatus::Invalid("truncated SNI list".to_string());
    }

    let mut names = &data[2..2 + list_len];
    while !names.is_empty() {
        if names.len() < 3 {
            return ClientHelloStatus::Invalid("truncated SNI name".to_string());
        }
        let name_type = names[0];
        let name_len = u16::from_be_bytes([names[1], names[2]]) as usize;
        if names.len() < 3 + name_len {
            return ClientHelloStatus::Invalid("truncated SNI host".to_string());
        }
        if name_type == 0 {
            let host = std::str::from_utf8(&names[3..3 + name_len])
                .map_err(|_| ())
                .and_then(|host| {
                    if host.is_empty() {
                        Err(())
                    } else {
                        Ok(host.to_string())
                    }
                });
            return match host {
                Ok(host) => ClientHelloStatus::Found(host),
                Err(()) => ClientHelloStatus::Invalid("invalid SNI hostname".to_string()),
            };
        }
        names = &names[3 + name_len..];
    }

    ClientHelloStatus::Invalid("DNS SNI name not found".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tls_sni_from_generated_client_hello() {
        let hello = synthetic_client_hello("example.com");
        assert_eq!(
            parse_tls_sni(&hello),
            ClientHelloStatus::Found("example.com".to_string())
        );
    }

    #[test]
    fn tls_parser_needs_more_for_partial_record() {
        let hello = synthetic_client_hello("example.com");
        assert_eq!(parse_tls_sni(&hello[..4]), ClientHelloStatus::NeedMore);
    }

    #[test]
    fn tls_parser_rejects_no_sni() {
        let hello = synthetic_client_hello_without_sni();
        assert!(matches!(
            parse_tls_sni(&hello),
            ClientHelloStatus::Invalid(_)
        ));
    }

    #[test]
    fn tls_parser_rejects_truncated_extension() {
        let mut hello = synthetic_client_hello("example.com");
        hello.pop();
        assert!(matches!(parse_tls_sni(&hello), ClientHelloStatus::NeedMore));
    }

    fn synthetic_client_hello(host: &str) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);

        let host = host.as_bytes();
        let mut sni = Vec::new();
        sni.extend_from_slice(&((3 + host.len()) as u16).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni.extend_from_slice(host);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0u16.to_be_bytes());
        extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        wrap_client_hello(body)
    }

    fn synthetic_client_hello_without_sni() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&0u16.to_be_bytes());
        wrap_client_hello(body)
    }

    fn wrap_client_hello(body: Vec<u8>) -> Vec<u8> {
        let mut handshake = vec![
            1,
            ((body.len() >> 16) & 0xff) as u8,
            ((body.len() >> 8) & 0xff) as u8,
            (body.len() & 0xff) as u8,
        ];
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(22);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }
}
