use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use crate::config::{
    canonicalize_source, config_filename, fetch_config, http_client, parse_yaml,
    warn_ignored_runtime_changes, ConfigSource, FileConfig, StaticSettings,
};
use crate::hosts::sync_hosts;
use crate::router::Runtime;

#[cfg(not(test))]
pub(crate) const CONFIG_FETCH_HARD_TIMEOUT: Duration = Duration::from_secs(15);
#[cfg(test)]
pub(crate) const CONFIG_FETCH_HARD_TIMEOUT: Duration = Duration::from_millis(100);

pub(crate) const MAX_IN_FLIGHT_FETCHES: usize = 2;

pub(crate) trait BlockingFetch: Send + Sync + 'static {
    fn fetch(&self, source: &ConfigSource) -> Result<String>;
}

pub(crate) struct DefaultFetcher;

impl BlockingFetch for DefaultFetcher {
    fn fetch(&self, source: &ConfigSource) -> Result<String> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .context("build config-fetch runtime")?;
        rt.block_on(async {
            let client = http_client()?;
            fetch_config(source, &client).await
        })
    }
}

pub(crate) struct InFlightFetches {
    current: AtomicUsize,
    max: usize,
}

pub(crate) struct InFlightGuard {
    slots: Arc<InFlightFetches>,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.slots.current.fetch_sub(1, Ordering::SeqCst);
    }
}

impl InFlightFetches {
    pub(crate) fn new(max: usize) -> Arc<Self> {
        Arc::new(Self {
            current: AtomicUsize::new(0),
            max,
        })
    }

    pub(crate) fn try_acquire(self: &Arc<Self>) -> Option<InFlightGuard> {
        loop {
            let cur = self.current.load(Ordering::SeqCst);
            if cur >= self.max {
                return None;
            }
            if self
                .current
                .compare_exchange(cur, cur + 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return Some(InFlightGuard {
                    slots: Arc::clone(self),
                });
            }
        }
    }

    pub(crate) fn count(&self) -> usize {
        self.current.load(Ordering::SeqCst)
    }
}

#[derive(Debug)]
pub(crate) enum FetchError {
    TimedOut(Duration),
    InFlight { current: usize },
    ThreadSpawn(std::io::Error),
    ThreadDropped,
    Failed(anyhow::Error),
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TimedOut(d) => write!(f, "config fetch timed out after {d:?}"),
            Self::InFlight { current } => {
                write!(f, "previous config fetch still in flight ({current})")
            }
            Self::ThreadSpawn(err) => write!(f, "spawn config fetch thread: {err}"),
            Self::ThreadDropped => write!(f, "config fetch thread panicked or dropped"),
            Self::Failed(err) => write!(f, "{err:#}"),
        }
    }
}

impl std::error::Error for FetchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Failed(err) => Some(err.as_ref()),
            Self::ThreadSpawn(err) => Some(err),
            _ => None,
        }
    }
}

pub(crate) async fn fetch_with_hard_timeout<F: BlockingFetch>(
    fetcher: Arc<F>,
    source: ConfigSource,
    in_flight: Arc<InFlightFetches>,
    hard_timeout: Duration,
) -> Result<String, FetchError> {
    let guard = match in_flight.try_acquire() {
        Some(guard) => guard,
        None => {
            return Err(FetchError::InFlight {
                current: in_flight.count(),
            });
        }
    };
    let (tx, rx) = tokio::sync::oneshot::channel();
    let fetch_source = source.clone();
    let started = Instant::now();
    let spawn = std::thread::Builder::new()
        .name("nyasniproxy-cfg-fetch".into())
        .spawn(move || {
            let _guard = guard;
            let result = fetcher.fetch(&fetch_source);
            let elapsed_ms = started.elapsed().as_millis() as u64;
            if tx.send(result).is_err() {
                debug!(elapsed_ms, "abandoned config fetch finished after timeout");
            }
        });
    match spawn {
        Ok(handle) => drop(handle),
        Err(err) => return Err(FetchError::ThreadSpawn(err)),
    }
    match tokio::time::timeout(hard_timeout, rx).await {
        Ok(Ok(Ok(text))) => Ok(text),
        Ok(Ok(Err(err))) => Err(FetchError::Failed(err)),
        Ok(Err(_)) => Err(FetchError::ThreadDropped),
        Err(_) => Err(FetchError::TimedOut(hard_timeout)),
    }
}

pub(crate) async fn run_reload_loop<F: BlockingFetch>(
    source: ConfigSource,
    fetcher: Arc<F>,
    settings: StaticSettings,
    runtime_tx: watch::Sender<Arc<Runtime>>,
    last_yaml: FileConfig,
    in_flight: Arc<InFlightFetches>,
) {
    match source {
        ConfigSource::File(path) => {
            if let Err(err) =
                watch_file(path, fetcher, settings, runtime_tx, last_yaml, in_flight).await
            {
                error!(error = %err, "config file watch stopped");
            }
        }
        ConfigSource::Url(url) => {
            poll_source(
                ConfigSource::Url(url),
                fetcher,
                settings,
                runtime_tx,
                last_yaml,
                in_flight,
            )
            .await;
        }
    }
}

async fn watch_file<F: BlockingFetch>(
    path: std::path::PathBuf,
    fetcher: Arc<F>,
    settings: StaticSettings,
    runtime_tx: watch::Sender<Arc<Runtime>>,
    mut last_yaml: FileConfig,
    in_flight: Arc<InFlightFetches>,
) -> Result<()> {
    let source = ConfigSource::File(path.clone());
    let filename = config_filename(&path).map(|name| name.to_os_string());
    let watch_dir = path
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."))
        .to_path_buf();

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let mut watcher: RecommendedWatcher = match notify::recommended_watcher(move |res| {
        let _ = tx.send(res);
    }) {
        Ok(watcher) => watcher,
        Err(err) => {
            warn!(error = %err, "file watch unavailable, polling config instead");
            poll_source(source, fetcher, settings, runtime_tx, last_yaml, in_flight).await;
            return Ok(());
        }
    };

    if let Err(err) = watcher.watch(&watch_dir, RecursiveMode::NonRecursive) {
        warn!(error = %err, "watch config directory failed, polling instead");
        poll_source(source, fetcher, settings, runtime_tx, last_yaml, in_flight).await;
        return Ok(());
    }

    info!(path = %path.display(), "watching config file");
    while let Some(event) = rx.recv().await {
        match event {
            Ok(event) if event_applies(&event, filename.as_deref()) => {
                tokio::time::sleep(Duration::from_millis(200)).await;
                while rx.try_recv().is_ok() {}
                reload_once(
                    &source,
                    &fetcher,
                    &settings,
                    &runtime_tx,
                    &mut last_yaml,
                    &in_flight,
                )
                .await;
            }
            Ok(_) => {}
            Err(err) => warn!(error = %err, "config watch event failed"),
        }
    }
    Ok(())
}

async fn poll_source<F: BlockingFetch>(
    source: ConfigSource,
    fetcher: Arc<F>,
    settings: StaticSettings,
    runtime_tx: watch::Sender<Arc<Runtime>>,
    mut last_yaml: FileConfig,
    in_flight: Arc<InFlightFetches>,
) {
    let mut interval = tokio::time::interval(settings.refresh);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    interval.tick().await;
    loop {
        interval.tick().await;
        reload_once(
            &source,
            &fetcher,
            &settings,
            &runtime_tx,
            &mut last_yaml,
            &in_flight,
        )
        .await;
    }
}

pub(crate) async fn reload_once<F: BlockingFetch>(
    source: &ConfigSource,
    fetcher: &Arc<F>,
    settings: &StaticSettings,
    runtime_tx: &watch::Sender<Arc<Runtime>>,
    last_yaml: &mut FileConfig,
    in_flight: &Arc<InFlightFetches>,
) {
    let started = Instant::now();
    let text = match fetch_with_hard_timeout(
        Arc::clone(fetcher),
        source.clone(),
        Arc::clone(in_flight),
        CONFIG_FETCH_HARD_TIMEOUT,
    )
    .await
    {
        Ok(text) => text,
        Err(FetchError::InFlight { current }) => {
            warn!(
                in_flight = current,
                elapsed_ms = started.elapsed().as_millis() as u64,
                source = %source,
                "config poll skipped"
            );
            return;
        }
        Err(err) => {
            error!(
                error = %err,
                elapsed_ms = started.elapsed().as_millis() as u64,
                source = %source,
                "config poll failed"
            );
            return;
        }
    };
    let yaml = match parse_yaml(&text) {
        Ok(yaml) => yaml,
        Err(err) => {
            error!(
                error = %err,
                elapsed_ms = started.elapsed().as_millis() as u64,
                source = %source,
                "config poll failed"
            );
            return;
        }
    };
    warn_ignored_runtime_changes(last_yaml, &yaml);
    let runtime = match Runtime::from_yaml(&yaml) {
        Ok(runtime) => runtime,
        Err(err) => {
            error!(
                error = %err,
                elapsed_ms = started.elapsed().as_millis() as u64,
                source = %source,
                "config poll failed"
            );
            return;
        }
    };

    let routing_changed = runtime_tx.borrow().fingerprint() != runtime.fingerprint();
    apply_hosts(settings, &runtime).await;
    if routing_changed {
        if runtime_tx.send(Arc::new(runtime)).is_err() {
            error!(
                elapsed_ms = started.elapsed().as_millis() as u64,
                source = %source,
                "config poll failed"
            );
            error!("runtime config receiver dropped");
            return;
        }
    }
    info!(
        source = %source,
        elapsed_ms = started.elapsed().as_millis() as u64,
        routing_changed,
        "config poll completed"
    );
    *last_yaml = yaml;
}

pub(crate) async fn apply_hosts(settings: &StaticSettings, runtime: &Runtime) {
    let Some(path) = settings.hosts_path.clone() else {
        return;
    };
    let listen = settings.listen;
    let hostnames = runtime.hostnames.clone();
    let path_display = path.display().to_string();
    match tokio::task::spawn_blocking(move || sync_hosts(&path, listen, &hostnames)).await {
        Ok(Ok(true)) => info!(path = %path_display, "hosts file updated"),
        Ok(Ok(false)) => debug!(path = %path_display, "hosts file already up to date"),
        Ok(Err(err)) => error!(error = %err, path = %path_display, "update hosts file failed"),
        Err(err) => error!(error = %err, path = %path_display, "hosts sync task failed"),
    }
}

fn event_applies(event: &Event, filename: Option<&std::ffi::OsStr>) -> bool {
    if !matches!(
        event.kind,
        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_) | EventKind::Any
    ) {
        return false;
    }
    let Some(filename) = filename else {
        return true;
    };
    event
        .paths
        .iter()
        .any(|path| path.file_name() == Some(filename))
}

pub(crate) async fn prepare_source(source: ConfigSource) -> ConfigSource {
    match canonicalize_source(source.clone()).await {
        Ok(source) => source,
        Err(err) => {
            debug!(error = %err, "keep original config path");
            source
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_yaml;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Mutex;
    use std::thread;
    use std::time::Duration;
    use tracing::Level;
    use tracing_subscriber::fmt::MakeWriter;

    fn sample_yaml() -> &'static str {
        r#"
proxies:
  jp: http://127.0.0.1:8080
  us: http://127.0.0.1:8081
rules:
  example.com: us
  default: jp
"#
    }

    fn other_yaml() -> &'static str {
        r#"
proxies:
  jp: http://127.0.0.1:8080
  us: http://127.0.0.1:8099
rules:
  example.com: us
  other.example: jp
  default: jp
"#
    }

    fn test_settings() -> StaticSettings {
        StaticSettings {
            listen: "127.0.0.1".parse().unwrap(),
            http: true,
            hosts_path: None,
            refresh: Duration::from_secs(30),
        }
    }

    fn seed_runtime() -> (
        FileConfig,
        watch::Sender<Arc<Runtime>>,
        watch::Receiver<Arc<Runtime>>,
        u64,
    ) {
        let yaml = parse_yaml(sample_yaml()).unwrap();
        let runtime = Runtime::from_yaml(&yaml).unwrap();
        let fingerprint = runtime.fingerprint();
        let (tx, rx) = watch::channel(Arc::new(runtime));
        (yaml, tx, rx, fingerprint)
    }

    struct SeqFetcher {
        calls: AtomicUsize,
    }

    impl SeqFetcher {
        fn sleep_then_yaml() -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
            })
        }
    }

    impl BlockingFetch for SeqFetcher {
        fn fetch(&self, _source: &ConfigSource) -> Result<String> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                thread::sleep(Duration::from_millis(250));
                return Ok(sample_yaml().to_string());
            }
            Ok(other_yaml().to_string())
        }
    }

    struct HangFetcher {
        calls: AtomicUsize,
        unpark: Mutex<Vec<thread::Thread>>,
    }

    impl HangFetcher {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                unpark: Mutex::new(Vec::new()),
            })
        }
    }

    impl BlockingFetch for HangFetcher {
        fn fetch(&self, _source: &ConfigSource) -> Result<String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.unpark.lock().unwrap().push(thread::current());
            loop {
                thread::park();
            }
        }
    }

    struct FailFetcher;

    impl BlockingFetch for FailFetcher {
        fn fetch(&self, _source: &ConfigSource) -> Result<String> {
            anyhow::bail!("synthetic fetch failure");
        }
    }

    struct YamlFetcher(&'static str);

    impl BlockingFetch for YamlFetcher {
        fn fetch(&self, _source: &ConfigSource) -> Result<String> {
            Ok(self.0.to_string())
        }
    }

    #[derive(Clone)]
    struct BufWriter(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for BufWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for BufWriter {
        type Writer = BufWriter;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    #[tokio::test]
    async fn reload_timeout_does_not_block_next_poll() {
        let fetcher = SeqFetcher::sleep_then_yaml();
        let (mut last_yaml, runtime_tx, _runtime_rx, before) = seed_runtime();
        let in_flight = InFlightFetches::new(MAX_IN_FLIGHT_FETCHES);
        let source = ConfigSource::parse("https://example.com/sni.yaml").unwrap();
        let settings = test_settings();

        reload_once(
            &source,
            &fetcher,
            &settings,
            &runtime_tx,
            &mut last_yaml,
            &in_flight,
        )
        .await;
        assert_eq!(runtime_tx.borrow().fingerprint(), before);

        tokio::time::timeout(Duration::from_secs(2), async {
            while in_flight.count() != 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("hung fetch thread should release its in-flight slot");

        reload_once(
            &source,
            &fetcher,
            &settings,
            &runtime_tx,
            &mut last_yaml,
            &in_flight,
        )
        .await;
        assert_ne!(runtime_tx.borrow().fingerprint(), before);
        assert_eq!(in_flight.count(), 0);
    }

    #[tokio::test]
    async fn poll_logs_completed_failed_and_skipped() {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(Level::TRACE)
            .with_ansi(false)
            .with_writer(BufWriter(Arc::clone(&buf)))
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let (mut last_yaml, runtime_tx, _runtime_rx, _) = seed_runtime();
        let in_flight = InFlightFetches::new(MAX_IN_FLIGHT_FETCHES);
        let source = ConfigSource::parse("https://example.com/sni.yaml").unwrap();
        let settings = test_settings();

        reload_once(
            &source,
            &Arc::new(YamlFetcher(sample_yaml())),
            &settings,
            &runtime_tx,
            &mut last_yaml,
            &in_flight,
        )
        .await;

        reload_once(
            &source,
            &Arc::new(FailFetcher),
            &settings,
            &runtime_tx,
            &mut last_yaml,
            &in_flight,
        )
        .await;
        {
            let logs = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
            assert!(
                logs.contains("config poll failed"),
                "missing failed log after FailFetcher: {logs}"
            );
        }

        let hang = HangFetcher::new();
        let f1 = {
            let hang = Arc::clone(&hang);
            let in_flight = Arc::clone(&in_flight);
            let source = source.clone();
            tokio::spawn(async move {
                fetch_with_hard_timeout(hang, source, in_flight, CONFIG_FETCH_HARD_TIMEOUT).await
            })
        };
        let f2 = {
            let hang = Arc::clone(&hang);
            let in_flight = Arc::clone(&in_flight);
            let source = source.clone();
            tokio::spawn(async move {
                fetch_with_hard_timeout(hang, source, in_flight, CONFIG_FETCH_HARD_TIMEOUT).await
            })
        };
        tokio::time::timeout(Duration::from_secs(1), async {
            while in_flight.count() < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        reload_once(
            &source,
            &hang,
            &settings,
            &runtime_tx,
            &mut last_yaml,
            &in_flight,
        )
        .await;
        let _ = f1.await;
        let _ = f2.await;

        let logs = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(
            logs.contains("config poll completed"),
            "missing completed log: {logs}"
        );
        assert!(
            logs.contains("routing_changed") && logs.contains("false")
                || logs.contains("routing_changed=false"),
            "unchanged routing should be visible at info: {logs}"
        );
        assert!(
            logs.contains("config poll failed"),
            "missing failed log: {logs}"
        );
        assert!(
            logs.contains("config poll skipped"),
            "missing skipped log: {logs}"
        );
    }

    #[tokio::test]
    async fn in_flight_cap_skips_third_fetch() {
        let hang = HangFetcher::new();
        let in_flight = InFlightFetches::new(MAX_IN_FLIGHT_FETCHES);
        let source = ConfigSource::parse("https://example.com/sni.yaml").unwrap();

        let t1 = {
            let hang = Arc::clone(&hang);
            let in_flight = Arc::clone(&in_flight);
            let source = source.clone();
            tokio::spawn(async move {
                fetch_with_hard_timeout(hang, source, in_flight, CONFIG_FETCH_HARD_TIMEOUT).await
            })
        };
        let t2 = {
            let hang = Arc::clone(&hang);
            let in_flight = Arc::clone(&in_flight);
            let source = source.clone();
            tokio::spawn(async move {
                fetch_with_hard_timeout(hang, source, in_flight, CONFIG_FETCH_HARD_TIMEOUT).await
            })
        };
        tokio::time::timeout(Duration::from_secs(1), async {
            while hang.calls.load(Ordering::SeqCst) < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("both hung fetches should enter fetch()");

        let third = fetch_with_hard_timeout(
            Arc::clone(&hang),
            source,
            Arc::clone(&in_flight),
            CONFIG_FETCH_HARD_TIMEOUT,
        )
        .await;
        assert!(
            matches!(third, Err(FetchError::InFlight { current: 2 })),
            "third fetch should be InFlight, got {third:?}"
        );
        assert_eq!(hang.calls.load(Ordering::SeqCst), 2);
        t1.abort();
        t2.abort();
    }
}
