use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use crate::config::{
    canonicalize_source, config_filename, fetch_config, parse_yaml, warn_ignored_runtime_changes,
    ConfigSource, FileConfig, StaticSettings,
};
use crate::hosts::sync_hosts;
use crate::router::Runtime;

pub(crate) async fn run_reload_loop(
    source: ConfigSource,
    client: reqwest::Client,
    settings: StaticSettings,
    runtime_tx: watch::Sender<Arc<Runtime>>,
    last_yaml: FileConfig,
) {
    match source {
        ConfigSource::File(path) => {
            if let Err(err) = watch_file(path, client, settings, runtime_tx, last_yaml).await {
                error!(error = %err, "config file watch stopped");
            }
        }
        ConfigSource::Url(url) => {
            poll_source(
                ConfigSource::Url(url),
                client,
                settings,
                runtime_tx,
                last_yaml,
            )
            .await;
        }
    }
}

async fn watch_file(
    path: std::path::PathBuf,
    client: reqwest::Client,
    settings: StaticSettings,
    runtime_tx: watch::Sender<Arc<Runtime>>,
    mut last_yaml: FileConfig,
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
            poll_source(source, client, settings, runtime_tx, last_yaml).await;
            return Ok(());
        }
    };

    if let Err(err) = watcher.watch(&watch_dir, RecursiveMode::NonRecursive) {
        warn!(error = %err, "watch config directory failed, polling instead");
        poll_source(source, client, settings, runtime_tx, last_yaml).await;
        return Ok(());
    }

    info!(path = %path.display(), "watching config file");
    while let Some(event) = rx.recv().await {
        match event {
            Ok(event) if event_applies(&event, filename.as_deref()) => {
                tokio::time::sleep(Duration::from_millis(200)).await;
                while rx.try_recv().is_ok() {}
                reload_once(&source, &client, &settings, &runtime_tx, &mut last_yaml).await;
            }
            Ok(_) => {}
            Err(err) => warn!(error = %err, "config watch event failed"),
        }
    }
    Ok(())
}

async fn poll_source(
    source: ConfigSource,
    client: reqwest::Client,
    settings: StaticSettings,
    runtime_tx: watch::Sender<Arc<Runtime>>,
    mut last_yaml: FileConfig,
) {
    let mut interval = tokio::time::interval(settings.refresh);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    interval.tick().await;
    loop {
        interval.tick().await;
        reload_once(&source, &client, &settings, &runtime_tx, &mut last_yaml).await;
    }
}

async fn reload_once(
    source: &ConfigSource,
    client: &reqwest::Client,
    settings: &StaticSettings,
    runtime_tx: &watch::Sender<Arc<Runtime>>,
    last_yaml: &mut FileConfig,
) {
    let text = match fetch_config(source, client).await {
        Ok(text) => text,
        Err(err) => {
            error!(error = %err, "reload config failed");
            return;
        }
    };
    let yaml = match parse_yaml(&text) {
        Ok(yaml) => yaml,
        Err(err) => {
            error!(error = %err, "reload config is invalid");
            return;
        }
    };
    warn_ignored_runtime_changes(last_yaml, &yaml);
    let runtime = match Runtime::from_yaml(&yaml) {
        Ok(runtime) => runtime,
        Err(err) => {
            error!(error = %err, "reload config is invalid");
            return;
        }
    };

    let routing_changed = runtime_tx.borrow().fingerprint() != runtime.fingerprint();
    apply_hosts(settings, &runtime);
    if routing_changed {
        if runtime_tx.send(Arc::new(runtime)).is_err() {
            error!("runtime config receiver dropped");
            return;
        }
        info!(source = %source, "config reloaded");
    } else {
        debug!("reloaded config routing is unchanged");
    }
    *last_yaml = yaml;
}

pub(crate) fn apply_hosts(settings: &StaticSettings, runtime: &Runtime) {
    let Some(path) = &settings.hosts_path else {
        return;
    };
    match sync_hosts(path, settings.listen, &runtime.hostnames) {
        Ok(true) => info!(path = %path.display(), "hosts file updated"),
        Ok(false) => debug!(path = %path.display(), "hosts file already up to date"),
        Err(err) => error!(error = %err, path = %path.display(), "update hosts file failed"),
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
