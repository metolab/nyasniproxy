mod config;
mod hosts;
mod http;
mod proxy;
mod reload;
mod router;
mod target;
mod tls;
mod watchdog;

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};
use tokio::time::{sleep, timeout, Instant};
use tracing::{debug, info};

use crate::config::{merge_settings, parse_yaml, CliOverrides, ConfigSource};
use crate::reload::{
    apply_hosts, fetch_with_hard_timeout, prepare_source, run_reload_loop, DefaultFetcher,
    InFlightFetches, CONFIG_FETCH_HARD_TIMEOUT,
};
use crate::router::{connect_with_fallback, Runtime};
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
    #[arg(long, help = "YAML config file path or HTTP(S) URL")]
    config: String,

    #[arg(long, help = "Loopback listen address")]
    listen: Option<IpAddr>,

    #[arg(long, conflicts_with = "no_hosts", help = "Hosts file to keep in sync")]
    hosts: Option<PathBuf>,

    #[arg(long, conflicts_with = "hosts", help = "Disable hosts file sync")]
    no_hosts: bool,

    #[arg(long, help = "Disable the HTTP listener on port 80")]
    no_http: bool,

    #[arg(
        long,
        help = "Seconds between remote config refreshes (default 30, overrides YAML)"
    )]
    refresh: Option<u64>,

    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(&cli.log_level)?;

    let overrides = CliOverrides {
        listen: cli.listen,
        hosts: cli.hosts.clone(),
        no_hosts: cli.no_hosts,
        no_http: cli.no_http,
        refresh: cli.refresh,
    };
    let heartbeat = watchdog::Heartbeat::new();
    let _watchdog = watchdog::spawn_watchdog(
        Arc::clone(&heartbeat),
        watchdog::WATCHDOG_STALL_TIMEOUT,
        watchdog::WATCHDOG_POLL_INTERVAL,
        || watchdog::watchdog_suicide(),
    );

    let source = ConfigSource::parse(&cli.config)?;
    let fetcher = Arc::new(DefaultFetcher);
    let in_flight = InFlightFetches::new(crate::reload::MAX_IN_FLIGHT_FETCHES);
    let text = fetch_with_hard_timeout(
        Arc::clone(&fetcher),
        source.clone(),
        Arc::clone(&in_flight),
        CONFIG_FETCH_HARD_TIMEOUT,
    )
    .await
    .map_err(|err| anyhow!("{err}"))?;
    heartbeat.beat();
    let yaml = parse_yaml(&text)?;
    let settings = merge_settings(&yaml, &overrides)?;
    let runtime = Runtime::from_yaml(&yaml)?;
    let source = prepare_source(source).await;
    heartbeat.beat();

    let connection_limit = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let https_listener = TcpListener::bind((settings.listen, 443))
        .await
        .with_context(|| format!("bind {}:443", settings.listen))?;
    let http_listener = if settings.http {
        Some(
            TcpListener::bind((settings.listen, 80))
                .await
                .with_context(|| format!("bind {}:80", settings.listen))?,
        )
    } else {
        None
    };
    heartbeat.beat();

    apply_hosts(&settings, &runtime).await;
    heartbeat.beat();

    info!(
        listen = %settings.listen,
        http = settings.http,
        hosts = ?settings.hosts_path,
        refresh_secs = settings.refresh.as_secs(),
        config = %source,
        worker_threads = std::thread::available_parallelism().ok().map(|n| n.get()),
        "nyasniproxy started"
    );

    let (runtime_tx, runtime_rx) = watch::channel(Arc::new(runtime));
    tokio::spawn(run_reload_loop(
        source,
        fetcher,
        settings.clone(),
        runtime_tx,
        yaml,
        in_flight,
    ));

    heartbeat.beat();
    if let Some(http_listener) = http_listener {
        tokio::try_join!(
            accept_loop(
                http_listener,
                InboundProtocol::Http,
                runtime_rx.clone(),
                Arc::clone(&connection_limit),
                Arc::clone(&heartbeat),
                #[cfg(test)]
                None,
            ),
            accept_loop(
                https_listener,
                InboundProtocol::Https,
                runtime_rx,
                connection_limit,
                heartbeat,
                #[cfg(test)]
                None,
            ),
        )?;
    } else {
        accept_loop(
            https_listener,
            InboundProtocol::Https,
            runtime_rx,
            connection_limit,
            heartbeat,
            #[cfg(test)]
            None,
        )
        .await?;
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
    runtime: watch::Receiver<Arc<Runtime>>,
    connection_limit: Arc<Semaphore>,
    heartbeat: Arc<watchdog::Heartbeat>,
    #[cfg(test)] accepted: Option<tokio::sync::mpsc::Sender<(TcpStream, std::net::SocketAddr)>>,
) -> Result<()> {
    let mut beat = tokio::time::interval(watchdog::ACCEPT_HEARTBEAT_INTERVAL);
    beat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            result = listener.accept() => {
                heartbeat.beat();
                let (stream, peer) = result?;
                #[cfg(test)]
                if let Some(tx) = &accepted {
                    let _ = tx.try_send((stream, peer));
                    continue;
                }
                let Ok(permit) = Arc::clone(&connection_limit).try_acquire_owned() else {
                    debug!(%peer, ?protocol, max_connections = MAX_CONNECTIONS, "connection limit reached");
                    continue;
                };
                let runtime = runtime.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(err) = handle_connection(stream, protocol, runtime).await {
                        debug!(%peer, ?protocol, error = %err, "connection closed");
                    }
                });
            }
            _ = beat.tick() => {
                heartbeat.beat();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::reload::{reload_once, BlockingFetch, MAX_IN_FLIGHT_FETCHES};
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
    use tokio::sync::mpsc;

    fn test_runtime(proxy_url: &str) -> watch::Receiver<Arc<Runtime>> {
        let runtime = Arc::new(Runtime::single_proxy(proxy_url).unwrap());
        let (_tx, rx) = watch::channel(runtime);
        rx
    }

    #[tokio::test]
    async fn handle_connection_times_out_reading_initial_http_header() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let _client = client;
        let runtime = test_runtime("http://127.0.0.1:9");

        let err = handle_connection(server, InboundProtocol::Http, runtime)
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

    struct FailFetcher;

    impl BlockingFetch for FailFetcher {
        fn fetch(&self, _source: &crate::config::ConfigSource) -> anyhow::Result<String> {
            anyhow::bail!("synthetic fetch failure");
        }
    }

    struct SlowFetcher;

    impl BlockingFetch for SlowFetcher {
        fn fetch(&self, _source: &crate::config::ConfigSource) -> anyhow::Result<String> {
            std::thread::sleep(CONFIG_FETCH_HARD_TIMEOUT + Duration::from_millis(50));
            anyhow::bail!("slow fetch")
        }
    }

    fn dummy_runtime() -> (watch::Sender<Arc<Runtime>>, watch::Receiver<Arc<Runtime>>) {
        let runtime = Arc::new(Runtime::single_proxy("http://127.0.0.1:9").unwrap());
        watch::channel(runtime)
    }

    #[tokio::test]
    async fn fetch_failure_does_not_stop_userspace_accept() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let heartbeat = watchdog::Heartbeat::new();
        let (runtime_tx, runtime_rx) = dummy_runtime();
        let before = runtime_tx.borrow().fingerprint();
        let limit = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let (tx, mut rx) = mpsc::channel(4);
        let loop_handle = tokio::spawn(accept_loop(
            listener,
            InboundProtocol::Http,
            runtime_rx,
            limit,
            Arc::clone(&heartbeat),
            Some(tx),
        ));

        let source = ConfigSource::parse("https://example.com/sni.yaml").unwrap();
        let settings = crate::config::StaticSettings {
            listen: "127.0.0.1".parse().unwrap(),
            http: true,
            hosts_path: None,
            refresh: Duration::from_secs(30),
        };
        let yaml = crate::config::parse_yaml(
            r#"
proxies:
  jp: http://127.0.0.1:8080
rules:
  default: jp
"#,
        )
        .unwrap();
        let mut last_yaml = yaml;
        let in_flight = InFlightFetches::new(MAX_IN_FLIGHT_FETCHES);

        reload_once(
            &source,
            &Arc::new(FailFetcher),
            &settings,
            &runtime_tx,
            &mut last_yaml,
            &in_flight,
        )
        .await;
        assert_eq!(runtime_tx.borrow().fingerprint(), before);

        reload_once(
            &source,
            &Arc::new(SlowFetcher),
            &settings,
            &runtime_tx,
            &mut last_yaml,
            &in_flight,
        )
        .await;
        assert_eq!(runtime_tx.borrow().fingerprint(), before);

        let _client = TcpStream::connect(addr).await.unwrap();
        let accepted = tokio::time::timeout(Duration::from_millis(200), rx.recv())
            .await
            .expect("accept_loop must poll listener.accept()")
            .expect("accepted stream");
        drop(accepted);
        loop_handle.abort();
    }

    #[tokio::test]
    async fn idle_accept_loop_beats_without_clients() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let heartbeat = watchdog::Heartbeat::new();
        let before = heartbeat.last_ms();

        let (_runtime_tx, runtime_rx) = dummy_runtime();
        let limit = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let (stall_tx, mut stall_rx) = tokio::sync::oneshot::channel();
        let _wd = watchdog::spawn_watchdog(
            Arc::clone(&heartbeat),
            watchdog::WATCHDOG_STALL_TIMEOUT,
            watchdog::WATCHDOG_POLL_INTERVAL,
            move || {
                let _ = stall_tx.send(());
            },
        );

        let loop_handle = tokio::spawn(accept_loop(
            listener,
            InboundProtocol::Http,
            runtime_rx,
            limit,
            Arc::clone(&heartbeat),
            None,
        ));

        tokio::time::sleep(watchdog::ACCEPT_HEARTBEAT_INTERVAL * 3).await;
        assert!(
            heartbeat.last_ms() > before,
            "idle accept tick must call beat() without clients"
        );

        tokio::time::sleep(watchdog::WATCHDOG_STALL_TIMEOUT * 3).await;
        assert!(
            stall_rx.try_recv().is_err(),
            "watchdog must not fire while idle accept_loop is being polled"
        );

        loop_handle.abort();
    }
}

async fn handle_connection(
    mut inbound: TcpStream,
    protocol: InboundProtocol,
    runtime: watch::Receiver<Arc<Runtime>>,
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

    let hops = runtime.borrow().router.lookup(&target.host).to_vec();
    info!(
        ?protocol,
        target = %format_target(&target),
        via = ?hops.iter().map(|hop| hop.name.as_str()).collect::<Vec<_>>(),
        "opening upstream tunnel"
    );
    let mut upstream = connect_with_fallback(&hops, &target).await?;
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
