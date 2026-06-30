mod http;
mod proxy;
mod target;
mod tls;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::{sleep, timeout, Instant};
use tracing::{debug, info};

use crate::proxy::ProxyConfig;
use crate::target::format_target;

const MAX_CONNECTIONS: usize = 1024;
#[cfg(not(test))]
const INITIAL_READ_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(test)]
const INITIAL_READ_TIMEOUT: Duration = Duration::from_millis(50);
#[cfg(not(test))]
const INITIAL_UPSTREAM_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(test)]
const INITIAL_UPSTREAM_WRITE_TIMEOUT: Duration = Duration::from_millis(50);
const RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "SNI/Host transparent loopback proxy to HTTP(S)/SOCKS5 upstreams"
)]
struct Cli {
    #[arg(long, default_value = "127.0.0.2")]
    listen: IpAddr,

    #[arg(long)]
    proxy: String,

    #[arg(long, default_value = "info")]
    log_level: String,

    #[arg(long, help = "Disable the HTTP listener on port 80")]
    no_http: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(&cli.log_level)?;

    if !cli.listen.is_loopback() {
        bail!("--listen must be a loopback address, got {}", cli.listen);
    }

    let proxy = Arc::new(ProxyConfig::parse(&cli.proxy)?);
    let connection_limit = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let https_listener = TcpListener::bind((cli.listen, 443))
        .await
        .with_context(|| format!("bind {}:443", cli.listen))?;

    info!(listen = %cli.listen, proxy = ?proxy, http = !cli.no_http, "nyasniproxy started");

    if cli.no_http {
        accept_loop(
            https_listener,
            InboundProtocol::Https,
            proxy,
            connection_limit,
        )
        .await?;
    } else {
        let http_listener = TcpListener::bind((cli.listen, 80))
            .await
            .with_context(|| format!("bind {}:80", cli.listen))?;

        tokio::try_join!(
            accept_loop(
                http_listener,
                InboundProtocol::Http,
                Arc::clone(&proxy),
                Arc::clone(&connection_limit),
            ),
            accept_loop(
                https_listener,
                InboundProtocol::Https,
                proxy,
                connection_limit
            ),
        )?;
    }

    Ok(())
}

fn init_tracing(level: &str) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(level)
        .try_init()
        .map_err(|err| anyhow!("initialize logging: {err}"))
}

#[derive(Clone, Copy, Debug)]
enum InboundProtocol {
    Http,
    Https,
}

async fn accept_loop(
    listener: TcpListener,
    protocol: InboundProtocol,
    proxy: Arc<ProxyConfig>,
    connection_limit: Arc<Semaphore>,
) -> Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let Ok(permit) = Arc::clone(&connection_limit).try_acquire_owned() else {
            debug!(%peer, ?protocol, max_connections = MAX_CONNECTIONS, "connection limit reached");
            continue;
        };
        let proxy = Arc::clone(&proxy);
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(err) = handle_connection(stream, protocol, proxy).await {
                debug!(%peer, ?protocol, error = %err, "connection closed");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn handle_connection_times_out_reading_initial_http_header() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let _client = client;
        let proxy = Arc::new(ProxyConfig::parse("http://127.0.0.1:9").unwrap());

        let err = handle_connection(server, InboundProtocol::Http, proxy)
            .await
            .unwrap_err();

        assert!(err.to_string().contains("timed out reading HTTP header"));
    }

    #[tokio::test]
    async fn relay_closes_after_idle_timeout() {
        let (mut inbound_client, inbound_proxy) = duplex(1024);
        let (upstream_proxy, mut upstream_server) = duplex(1024);

        let relay = tokio::spawn(async move {
            let mut inbound_proxy = inbound_proxy;
            let mut upstream_proxy = upstream_proxy;
            copy_bidirectional_with_idle_timeout(
                &mut inbound_proxy,
                &mut upstream_proxy,
                Duration::from_millis(30),
            )
            .await
        });

        inbound_client.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        upstream_server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        let err = relay.await.unwrap().unwrap_err();
        assert!(err.to_string().contains("relay idle timeout"));
    }

    #[tokio::test]
    async fn relay_resets_idle_timeout_when_traffic_flows() {
        let (mut inbound_client, inbound_proxy) = duplex(1024);
        let (upstream_proxy, mut upstream_server) = duplex(1024);

        let relay = tokio::spawn(async move {
            let mut inbound_proxy = inbound_proxy;
            let mut upstream_proxy = upstream_proxy;
            copy_bidirectional_with_idle_timeout(
                &mut inbound_proxy,
                &mut upstream_proxy,
                Duration::from_millis(80),
            )
            .await
        });

        for byte in b"abc" {
            inbound_client.write_all(&[*byte]).await.unwrap();
            let mut buf = [0u8; 1];
            upstream_server.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf[0], *byte);
            tokio::time::sleep(Duration::from_millis(30)).await;
        }

        drop(inbound_client);
        drop(upstream_server);
        let result = relay.await.unwrap().unwrap();
        assert_eq!(result.0, 3);
    }
}

async fn handle_connection(
    mut inbound: TcpStream,
    protocol: InboundProtocol,
    proxy: Arc<ProxyConfig>,
) -> Result<()> {
    let (target, initial) = match protocol {
        InboundProtocol::Http => {
            timeout(INITIAL_READ_TIMEOUT, http::read_http_target(&mut inbound))
                .await
                .context("timed out reading HTTP header")??
        }
        InboundProtocol::Https => {
            timeout(INITIAL_READ_TIMEOUT, tls::read_https_target(&mut inbound))
                .await
                .context("timed out reading TLS ClientHello")??
        }
    };

    info!(?protocol, target = %format_target(&target), "opening upstream tunnel");
    let mut upstream = proxy.connect(&target).await?;
    timeout(INITIAL_UPSTREAM_WRITE_TIMEOUT, upstream.write_all(&initial))
        .await
        .context("timed out writing initial traffic upstream")??;

    let (from_client, from_server) =
        copy_bidirectional_with_idle_timeout(&mut inbound, &mut upstream, RELAY_IDLE_TIMEOUT)
            .await
            .context("relay traffic")?;
    debug!(?protocol, target = %format_target(&target), from_client, from_server, "relay complete");

    Ok(())
}

async fn copy_bidirectional_with_idle_timeout<A, B>(
    a: &mut A,
    b: &mut B,
    idle_timeout: Duration,
) -> Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut a_read, mut a_write) = tokio::io::split(a);
    let (mut b_read, mut b_write) = tokio::io::split(b);
    let mut a_to_b = 0;
    let mut b_to_a = 0;
    let mut a_done = false;
    let mut b_done = false;
    let mut a_buf = [0u8; 16 * 1024];
    let mut b_buf = [0u8; 16 * 1024];
    let idle = sleep(idle_timeout);
    tokio::pin!(idle);

    loop {
        if a_done && b_done {
            return Ok((a_to_b, b_to_a));
        }

        tokio::select! {
            () = &mut idle => {
                bail!("relay idle timeout");
            }
            result = a_read.read(&mut a_buf), if !a_done => {
                let n = result.context("read inbound traffic")?;
                if n == 0 {
                    a_done = true;
                    b_write.shutdown().await.context("shutdown upstream write side")?;
                } else {
                    b_write.write_all(&a_buf[..n]).await.context("write upstream traffic")?;
                    a_to_b += n as u64;
                    idle.as_mut().reset(Instant::now() + idle_timeout);
                }
            }
            result = b_read.read(&mut b_buf), if !b_done => {
                let n = result.context("read upstream traffic")?;
                if n == 0 {
                    b_done = true;
                    a_write.shutdown().await.context("shutdown inbound write side")?;
                } else {
                    a_write.write_all(&b_buf[..n]).await.context("write inbound traffic")?;
                    b_to_a += n as u64;
                    idle.as_mut().reset(Instant::now() + idle_timeout);
                }
            }
        }
    }
}
