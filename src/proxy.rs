use std::fmt::{self, Write as _};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use url::Url;

use crate::http::{header_end, MAX_HTTP_HEADER};
use crate::target::{format_target, Target};

#[derive(Clone, Debug)]
enum ProxyKind {
    Http,
    Https,
    Socks5,
}

#[derive(Clone)]
pub(crate) struct ProxyConfig {
    kind: ProxyKind,
    host: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    tls_connector: Option<TlsConnector>,
}

impl fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyConfig")
            .field("kind", &self.kind)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username.as_ref().map(|_| "<redacted>"))
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl ProxyConfig {
    pub(crate) fn parse(raw: &str) -> Result<Self> {
        let url = Url::parse(raw).context("parse --proxy URL")?;
        let kind = match url.scheme() {
            "http" => ProxyKind::Http,
            "https" => ProxyKind::Https,
            "socks5" => ProxyKind::Socks5,
            scheme => bail!("unsupported proxy scheme: {scheme}"),
        };
        let host = url
            .host_str()
            .ok_or_else(|| anyhow!("proxy URL missing host"))?
            .to_string();
        let port = url
            .port_or_known_default()
            .ok_or_else(|| anyhow!("proxy URL missing port and scheme has no known default"))?;
        let username = if url.username().is_empty() {
            None
        } else {
            Some(url.username().to_string())
        };
        let password = url.password().map(ToString::to_string);
        let tls_connector = matches!(kind, ProxyKind::Https)
            .then(|| TlsConnector::from(Arc::new(tls_client_config())));

        Ok(Self {
            kind,
            host,
            port,
            username,
            password,
            tls_connector,
        })
    }

    pub(crate) async fn connect(&self, target: &Target) -> Result<ProxyStream> {
        match self.kind {
            ProxyKind::Http => {
                let mut stream = TcpStream::connect((self.host.as_str(), self.port))
                    .await
                    .with_context(|| format!("connect HTTP proxy {}:{}", self.host, self.port))?;
                let prefix = self.http_connect(&mut stream, target).await?;
                Ok(ProxyStream::Plain(PrefixedStream::new(stream, prefix)))
            }
            ProxyKind::Https => {
                let stream = TcpStream::connect((self.host.as_str(), self.port))
                    .await
                    .with_context(|| format!("connect HTTPS proxy {}:{}", self.host, self.port))?;
                let connector = self
                    .tls_connector
                    .clone()
                    .ok_or_else(|| anyhow!("HTTPS proxy connector missing"))?;
                let dns_name = ServerName::try_from(self.host.clone())
                    .context("HTTPS proxy host is not a valid TLS server name")?;
                let mut stream = connector
                    .connect(dns_name, stream)
                    .await
                    .context("TLS handshake with HTTPS proxy")?;
                let prefix = self.http_connect(&mut stream, target).await?;
                Ok(ProxyStream::Tls(Box::new(PrefixedStream::new(
                    stream, prefix,
                ))))
            }
            ProxyKind::Socks5 => {
                let mut stream = TcpStream::connect((self.host.as_str(), self.port))
                    .await
                    .with_context(|| format!("connect SOCKS5 proxy {}:{}", self.host, self.port))?;
                self.socks5_connect(&mut stream, target).await?;
                Ok(ProxyStream::Plain(PrefixedStream::new(stream, Vec::new())))
            }
        }
    }

    async fn http_connect<S>(&self, stream: &mut S, target: &Target) -> Result<Vec<u8>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let target_addr = format_target(target);
        let mut request = format!(
            "CONNECT {target_addr} HTTP/1.1\r\nHost: {target_addr}\r\nProxy-Connection: Keep-Alive\r\n"
        );
        if let Some(auth) = self.basic_auth_header() {
            let _ = write!(request, "Proxy-Authorization: Basic {auth}\r\n");
        }
        request.push_str("\r\n");
        stream.write_all(request.as_bytes()).await?;

        let response = read_connect_response(stream).await?;
        let head =
            std::str::from_utf8(&response.header).context("CONNECT response is not UTF-8")?;
        let status = head
            .lines()
            .next()
            .ok_or_else(|| anyhow!("empty CONNECT response"))?;
        if status.split_whitespace().nth(1) != Some("200") {
            bail!("HTTP proxy CONNECT failed: {status}");
        }

        Ok(response.leftover)
    }

    fn basic_auth_header(&self) -> Option<String> {
        let username = self.username.as_ref()?;
        let password = self.password.as_deref().unwrap_or("");
        let raw = format!("{username}:{password}");
        Some(base64::engine::general_purpose::STANDARD.encode(raw))
    }

    async fn socks5_connect(&self, stream: &mut TcpStream, target: &Target) -> Result<()> {
        let username = self.username.as_deref();
        let password = self.password.as_deref().unwrap_or("");
        if let Some(username) = username {
            stream.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
            let mut selected = [0u8; 2];
            stream.read_exact(&mut selected).await?;
            match selected {
                [0x05, 0x02] => {
                    let username = username.as_bytes();
                    let password = password.as_bytes();
                    if username.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
                        bail!("SOCKS5 username/password must be <= 255 bytes");
                    }
                    let mut auth = Vec::with_capacity(3 + username.len() + password.len());
                    auth.push(0x01);
                    auth.push(username.len() as u8);
                    auth.extend_from_slice(username);
                    auth.push(password.len() as u8);
                    auth.extend_from_slice(password);
                    stream.write_all(&auth).await?;
                    let mut auth_status = [0u8; 2];
                    stream.read_exact(&mut auth_status).await?;
                    if auth_status != [0x01, 0x00] {
                        bail!("SOCKS5 username/password authentication failed");
                    }
                }
                [0x05, 0x00] => {}
                [0x05, 0xff] => bail!("SOCKS5 proxy rejected authentication methods"),
                _ => bail!("invalid SOCKS5 method selection response"),
            }
        } else {
            stream.write_all(&[0x05, 0x01, 0x00]).await?;
            let mut selected = [0u8; 2];
            stream.read_exact(&mut selected).await?;
            if selected != [0x05, 0x00] {
                bail!("SOCKS5 proxy requires unsupported authentication");
            }
        }

        let host = target.host.as_bytes();
        if host.len() > u8::MAX as usize {
            bail!("SOCKS5 target host is too long");
        }
        let mut request = Vec::with_capacity(7 + host.len());
        request.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, host.len() as u8]);
        request.extend_from_slice(host);
        request.extend_from_slice(&target.port.to_be_bytes());
        stream.write_all(&request).await?;

        let mut head = [0u8; 4];
        stream.read_exact(&mut head).await?;
        if head[0] != 0x05 {
            bail!("invalid SOCKS5 response version");
        }
        if head[1] != 0x00 {
            bail!("SOCKS5 connect failed with code 0x{:02x}", head[1]);
        }
        let addr_len = match head[3] {
            0x01 => 4,
            0x03 => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                len[0] as usize
            }
            0x04 => 16,
            atyp => bail!("invalid SOCKS5 address type 0x{atyp:02x}"),
        };
        let mut skip = vec![0u8; addr_len + 2];
        stream.read_exact(&mut skip).await?;
        Ok(())
    }
}

struct ConnectResponse {
    header: Vec<u8>,
    leftover: Vec<u8>,
}

async fn read_connect_response<S>(stream: &mut S) -> Result<ConnectResponse>
where
    S: AsyncRead + Unpin,
{
    let mut response = Vec::with_capacity(1024);
    let mut buf = [0u8; 512];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            bail!("HTTP proxy closed before CONNECT response");
        }
        response.extend_from_slice(&buf[..n]);
        if let Some(end) = header_end(&response) {
            let leftover = response.split_off(end + 4);
            response.truncate(end);
            return Ok(ConnectResponse {
                header: response,
                leftover,
            });
        }
        if response.len() > MAX_HTTP_HEADER {
            bail!("HTTP proxy CONNECT response too large");
        }
    }
}

fn tls_client_config() -> ClientConfig {
    let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

pub(crate) struct PrefixedStream<S> {
    stream: S,
    prefix: Vec<u8>,
    prefix_offset: usize,
}

impl<S> PrefixedStream<S> {
    fn new(stream: S, prefix: Vec<u8>) -> Self {
        Self {
            stream,
            prefix,
            prefix_offset: 0,
        }
    }
}

impl<S> AsyncRead for PrefixedStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.prefix_offset < self.prefix.len() && buf.remaining() > 0 {
            let available = &self.prefix[self.prefix_offset..];
            let n = available.len().min(buf.remaining());
            buf.put_slice(&available[..n]);
            self.prefix_offset += n;
            if self.prefix_offset == self.prefix.len() {
                self.prefix.clear();
                self.prefix_offset = 0;
            }
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for PrefixedStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

pub(crate) enum ProxyStream {
    Plain(PrefixedStream<TcpStream>),
    Tls(Box<PrefixedStream<tokio_rustls::client::TlsStream<TcpStream>>>),
}

impl AsyncRead for ProxyStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ProxyStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::net::TcpListener;

    use super::*;

    #[test]
    fn parses_proxy_url_with_auth() {
        let proxy = ProxyConfig::parse("https://user:pass@proxy.example:8443").unwrap();
        assert!(matches!(proxy.kind, ProxyKind::Https));
        assert_eq!(proxy.host, "proxy.example");
        assert_eq!(proxy.port, 8443);
        assert_eq!(proxy.username.as_deref(), Some("user"));
        assert_eq!(proxy.password.as_deref(), Some("pass"));
        assert!(proxy.tls_connector.is_some());
    }

    #[test]
    fn rejects_unknown_proxy_scheme() {
        assert!(ProxyConfig::parse("ftp://proxy.example:21").is_err());
    }

    #[tokio::test]
    async fn http_connect_sends_connect_and_auth() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 256];
            loop {
                let n = stream.read(&mut buf).await.unwrap();
                request.extend_from_slice(&buf[..n]);
                if header_end(&request).is_some() {
                    break;
                }
            }
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            String::from_utf8(request).unwrap()
        });

        let proxy = ProxyConfig::parse(&format!("http://user:pass@127.0.0.1:{port}")).unwrap();
        let target = Target {
            host: "example.com".to_string(),
            port: 443,
        };
        let mut tunnel = proxy.connect(&target).await.unwrap();
        tunnel.shutdown().await.unwrap();

        let request = server.await.unwrap();
        assert!(request.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
        assert!(request.contains("Host: example.com:443\r\n"));
        assert!(request.contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"));
    }

    #[tokio::test]
    async fn http_connect_preserves_first_tunnel_byte_after_response() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 256];
            loop {
                let n = stream.read(&mut buf).await.unwrap();
                request.extend_from_slice(&buf[..n]);
                if header_end(&request).is_some() {
                    break;
                }
            }
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\nX")
                .await
                .unwrap();
        });

        let proxy = ProxyConfig::parse(&format!("http://127.0.0.1:{port}")).unwrap();
        let target = Target {
            host: "example.com".to_string(),
            port: 443,
        };
        let mut tunnel = proxy.connect(&target).await.unwrap();
        let mut byte = [0u8; 1];
        tunnel.read_exact(&mut byte).await.unwrap();
        assert_eq!(byte, [b'X']);
        tunnel.shutdown().await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn socks5_connect_uses_domain_name_and_auth() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut methods = [0u8; 4];
            stream.read_exact(&mut methods).await.unwrap();
            assert_eq!(methods, [0x05, 0x02, 0x00, 0x02]);
            stream.write_all(&[0x05, 0x02]).await.unwrap();

            let mut auth_head = [0u8; 2];
            stream.read_exact(&mut auth_head).await.unwrap();
            assert_eq!(auth_head, [0x01, 0x04]);
            let mut username = [0u8; 4];
            stream.read_exact(&mut username).await.unwrap();
            assert_eq!(&username, b"user");
            let mut pass_len = [0u8; 1];
            stream.read_exact(&mut pass_len).await.unwrap();
            assert_eq!(pass_len, [0x04]);
            let mut password = [0u8; 4];
            stream.read_exact(&mut password).await.unwrap();
            assert_eq!(&password, b"pass");
            stream.write_all(&[0x01, 0x00]).await.unwrap();

            let mut connect_head = [0u8; 5];
            stream.read_exact(&mut connect_head).await.unwrap();
            assert_eq!(connect_head, [0x05, 0x01, 0x00, 0x03, 11]);
            let mut host = [0u8; 11];
            stream.read_exact(&mut host).await.unwrap();
            assert_eq!(&host, b"example.com");
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await.unwrap();
            assert_eq!(u16::from_be_bytes(port), 443);
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x12, 0x34])
                .await
                .unwrap();
        });

        let proxy = ProxyConfig::parse(&format!("socks5://user:pass@127.0.0.1:{port}")).unwrap();
        let target = Target {
            host: "example.com".to_string(),
            port: 443,
        };
        let mut tunnel = proxy.connect(&target).await.unwrap();
        tunnel.shutdown().await.unwrap();
        server.await.unwrap();
    }
}
