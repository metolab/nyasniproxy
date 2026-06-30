mod http;
mod proxy;
mod target;
mod tls;

use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info};

use crate::proxy::ProxyConfig;
use crate::target::format_target;

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
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(&cli.log_level)?;

    if !cli.listen.is_loopback() {
        bail!("--listen must be a loopback address, got {}", cli.listen);
    }

    let proxy = Arc::new(ProxyConfig::parse(&cli.proxy)?);
    let http_listener = TcpListener::bind((cli.listen, 80))
        .await
        .with_context(|| format!("bind {}:80", cli.listen))?;
    let https_listener = TcpListener::bind((cli.listen, 443))
        .await
        .with_context(|| format!("bind {}:443", cli.listen))?;

    info!(listen = %cli.listen, proxy = ?proxy, "nyasniproxy started");

    tokio::try_join!(
        accept_loop(http_listener, InboundProtocol::Http, Arc::clone(&proxy)),
        accept_loop(https_listener, InboundProtocol::Https, proxy),
    )?;

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
) -> Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let proxy = Arc::clone(&proxy);
        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream, protocol, proxy).await {
                debug!(%peer, ?protocol, error = %err, "connection closed");
            }
        });
    }
}

async fn handle_connection(
    mut inbound: TcpStream,
    protocol: InboundProtocol,
    proxy: Arc<ProxyConfig>,
) -> Result<()> {
    let (target, initial) = match protocol {
        InboundProtocol::Http => http::read_http_target(&mut inbound).await?,
        InboundProtocol::Https => tls::read_https_target(&mut inbound).await?,
    };

    info!(?protocol, target = %format_target(&target), "opening upstream tunnel");
    let mut upstream = proxy.connect(&target).await?;
    upstream.write_all(&initial).await?;

    let (from_client, from_server) = tokio::io::copy_bidirectional(&mut inbound, &mut upstream)
        .await
        .context("relay traffic")?;
    debug!(?protocol, target = %format_target(&target), from_client, from_server, "relay complete");

    Ok(())
}
