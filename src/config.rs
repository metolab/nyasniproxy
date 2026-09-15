use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use url::Url;

const DEFAULT_LISTEN: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 2));
const DEFAULT_REFRESH_SECS: u64 = 30;
pub(crate) const MAX_CONFIG_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug)]
pub(crate) enum ConfigSource {
    File(PathBuf),
    Url(Url),
}

impl ConfigSource {
    pub(crate) fn parse(raw: &str) -> Result<Self> {
        if raw.starts_with("http://") || raw.starts_with("https://") {
            Ok(Self::Url(Url::parse(raw).context("parse config URL")?))
        } else {
            Ok(Self::File(PathBuf::from(raw)))
        }
    }
}

impl fmt::Display for ConfigSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File(path) => write!(f, "{}", path.display()),
            Self::Url(url) => write!(f, "{url}"),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct CliOverrides {
    pub(crate) listen: Option<IpAddr>,
    pub(crate) hosts: Option<PathBuf>,
    pub(crate) no_hosts: bool,
    pub(crate) no_http: bool,
    pub(crate) refresh: Option<u64>,
}

#[derive(Clone, Debug)]
pub(crate) struct StaticSettings {
    pub(crate) listen: IpAddr,
    pub(crate) http: bool,
    pub(crate) hosts_path: Option<PathBuf>,
    pub(crate) refresh: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum HostsSetting {
    Disabled,
    Path(PathBuf),
}

impl<'de> Deserialize<'de> for HostsSetting {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct HostsVisitor;

        impl<'de> Visitor<'de> for HostsVisitor {
            type Value = HostsSetting;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a hosts file path or false")
            }

            fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
                if value {
                    Err(E::custom("hosts: true is invalid; use a path or false"))
                } else {
                    Ok(HostsSetting::Disabled)
                }
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                if value.is_empty() {
                    return Err(E::custom("hosts path must not be empty"));
                }
                Ok(HostsSetting::Path(PathBuf::from(value)))
            }

            fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
                self.visit_str(&value)
            }
        }

        deserializer.deserialize_any(HostsVisitor)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProxyRef(pub(crate) Vec<String>);

impl<'de> Deserialize<'de> for ProxyRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ProxyRefVisitor;

        impl<'de> Visitor<'de> for ProxyRefVisitor {
            type Value = ProxyRef;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a proxy name or a list of proxy names")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                if value.is_empty() {
                    return Err(E::custom("proxy name must not be empty"));
                }
                Ok(ProxyRef(vec![value.to_string()]))
            }

            fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
                self.visit_str(&value)
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut names = Vec::new();
                while let Some(name) = seq.next_element::<String>()? {
                    if name.is_empty() {
                        return Err(de::Error::custom("proxy name must not be empty"));
                    }
                    names.push(name);
                }
                if names.is_empty() {
                    return Err(de::Error::custom("proxy list must not be empty"));
                }
                Ok(ProxyRef(names))
            }
        }

        deserializer.deserialize_any(ProxyRefVisitor)
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FileConfig {
    pub(crate) listen: Option<IpAddr>,
    pub(crate) hosts: Option<HostsSetting>,
    pub(crate) refresh: Option<u64>,
    pub(crate) http: Option<bool>,
    pub(crate) proxies: HashMap<String, String>,
    pub(crate) rules: HashMap<String, ProxyRef>,
}

pub(crate) fn parse_yaml(text: &str) -> Result<FileConfig> {
    let cfg: FileConfig = serde_yaml::from_str(text).context("parse YAML config")?;
    if cfg.proxies.is_empty() {
        bail!("proxies must not be empty");
    }
    if cfg.proxies.keys().any(|name| name.is_empty()) {
        bail!("proxy name must not be empty");
    }
    if !cfg
        .rules
        .keys()
        .any(|key| key.eq_ignore_ascii_case("default"))
    {
        bail!("rules.default is required");
    }
    Ok(cfg)
}

pub(crate) async fn fetch_config(
    source: &ConfigSource,
    client: &reqwest::Client,
) -> Result<String> {
    fetch_config_limited(source, client, MAX_CONFIG_BYTES).await
}

pub(crate) async fn fetch_config_limited(
    source: &ConfigSource,
    client: &reqwest::Client,
    max_bytes: usize,
) -> Result<String> {
    match source {
        ConfigSource::File(path) => read_file_limited(path, max_bytes).await,
        ConfigSource::Url(url) => fetch_url_limited(client, url, max_bytes).await,
    }
}

async fn read_file_limited(path: &Path, max_bytes: usize) -> Result<String> {
    use tokio::io::AsyncReadExt;

    let file = tokio::fs::File::open(path)
        .await
        .with_context(|| format!("read config {}", path.display()))?;
    let mut buf = Vec::new();
    file.take(max_bytes as u64 + 1)
        .read_to_end(&mut buf)
        .await
        .with_context(|| format!("read config {}", path.display()))?;
    if buf.len() > max_bytes {
        bail!("config {} exceeds {max_bytes} bytes", path.display());
    }
    String::from_utf8(buf).context("config is not valid UTF-8")
}

async fn fetch_url_limited(
    client: &reqwest::Client,
    url: &Url,
    max_bytes: usize,
) -> Result<String> {
    let response = client
        .get(url.clone())
        .send()
        .await
        .with_context(|| format!("fetch config URL {url}"))?;
    let status = response.status();
    if !status.is_success() {
        bail!("fetch config URL {url} returned {status}");
    }
    if let Some(len) = response.content_length() {
        if len > max_bytes as u64 {
            bail!("config URL {url} is larger than {max_bytes} bytes");
        }
    }

    let mut buf = Vec::new();
    let mut response = response;
    while let Some(chunk) = response
        .chunk()
        .await
        .with_context(|| format!("read config URL {url} body"))?
    {
        if buf.len().saturating_add(chunk.len()) > max_bytes {
            bail!("config URL {url} exceeds {max_bytes} bytes");
        }
        buf.extend_from_slice(&chunk);
    }
    String::from_utf8(buf).context("config URL body is not valid UTF-8")
}

pub(crate) fn merge_settings(yaml: &FileConfig, cli: &CliOverrides) -> Result<StaticSettings> {
    let listen = cli.listen.or(yaml.listen).unwrap_or(DEFAULT_LISTEN);
    if !listen.is_loopback() {
        bail!("listen must be a loopback address, got {listen}");
    }

    let http = if cli.no_http {
        false
    } else {
        yaml.http.unwrap_or(true)
    };

    let hosts_path = if cli.no_hosts {
        None
    } else if let Some(path) = &cli.hosts {
        Some(path.clone())
    } else {
        match &yaml.hosts {
            Some(HostsSetting::Disabled) => None,
            Some(HostsSetting::Path(path)) => Some(path.clone()),
            None => Some(default_hosts_path()),
        }
    };

    let refresh_secs = cli.refresh.or(yaml.refresh).unwrap_or(DEFAULT_REFRESH_SECS);
    if refresh_secs == 0 {
        bail!("refresh must be greater than 0 seconds");
    }

    Ok(StaticSettings {
        listen,
        http,
        hosts_path,
        refresh: Duration::from_secs(refresh_secs),
    })
}

pub(crate) fn default_hosts_path() -> PathBuf {
    #[cfg(windows)]
    {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
        PathBuf::from(root).join(r"System32\drivers\etc\hosts")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/etc/hosts")
    }
}

pub(crate) fn warn_ignored_runtime_changes(prev: &FileConfig, next: &FileConfig) {
    if prev.listen != next.listen {
        tracing::warn!("ignoring listen change in reloaded config; restart to apply");
    }
    if prev.http != next.http {
        tracing::warn!("ignoring http change in reloaded config; restart to apply");
    }
    if prev.hosts != next.hosts {
        tracing::warn!("ignoring hosts change in reloaded config; restart to apply");
    }
    if prev.refresh != next.refresh {
        tracing::warn!("ignoring refresh change in reloaded config; restart to apply");
    }
}

pub(crate) fn http_client() -> Result<reqwest::Client> {
    crate::proxy::ensure_crypto_provider();
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(5))
        .build()
        .map_err(|err| anyhow!("build HTTP client: {err}"))
}

pub(crate) async fn canonicalize_source(source: ConfigSource) -> Result<ConfigSource> {
    match source {
        ConfigSource::File(path) => Ok(ConfigSource::File(
            tokio::fs::canonicalize(&path)
                .await
                .with_context(|| format!("canonicalize config {}", path.display()))?,
        )),
        other => Ok(other),
    }
}

pub(crate) fn config_filename(path: &Path) -> Option<&std::ffi::OsStr> {
    path.file_name()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::header_end;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn sample_yaml() -> &'static str {
        r#"
proxies:
  jp: http://127.0.0.1:8080
  us: http://127.0.0.1:8081
rules:
  example.com: us
  www.example.com: [us, jp]
  default: jp
"#
    }

    #[test]
    fn parses_string_and_list_rules() {
        let cfg = parse_yaml(sample_yaml()).unwrap();
        assert_eq!(cfg.proxies.len(), 2);
        assert_eq!(cfg.rules["example.com"].0, vec!["us".to_string()]);
        assert_eq!(
            cfg.rules["www.example.com"].0,
            vec!["us".to_string(), "jp".to_string()]
        );
        assert_eq!(cfg.rules["default"].0, vec!["jp".to_string()]);
    }

    #[test]
    fn rejects_missing_default() {
        let err = parse_yaml(
            r#"
proxies:
  jp: http://127.0.0.1:8080
rules:
  example.com: jp
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("rules.default is required"));
    }

    #[test]
    fn rejects_empty_proxies() {
        let err = parse_yaml(
            r#"
proxies: {}
rules:
  default: jp
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("proxies must not be empty"));
    }

    #[test]
    fn parses_hosts_false() {
        let cfg = parse_yaml(
            r#"
hosts: false
proxies:
  jp: http://127.0.0.1:8080
rules:
  default: jp
"#,
        )
        .unwrap();
        assert_eq!(cfg.hosts, Some(HostsSetting::Disabled));
    }

    #[test]
    fn merge_prefers_cli_over_yaml() {
        let yaml = parse_yaml(
            r#"
listen: 127.0.0.3
hosts: /tmp/hosts
refresh: 9
http: true
proxies:
  jp: http://127.0.0.1:8080
rules:
  default: jp
"#,
        )
        .unwrap();
        let settings = merge_settings(
            &yaml,
            &CliOverrides {
                listen: Some("127.0.0.2".parse().unwrap()),
                hosts: Some(PathBuf::from("/var/hosts")),
                no_hosts: false,
                no_http: true,
                refresh: Some(30),
            },
        )
        .unwrap();
        assert_eq!(settings.listen, "127.0.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(
            settings.hosts_path.as_deref(),
            Some(Path::new("/var/hosts"))
        );
        assert!(!settings.http);
        assert_eq!(settings.refresh, Duration::from_secs(30));
    }

    #[test]
    fn merge_uses_yaml_then_defaults() {
        let yaml = parse_yaml(sample_yaml()).unwrap();
        let settings = merge_settings(&yaml, &CliOverrides::default()).unwrap();
        assert_eq!(settings.listen, DEFAULT_LISTEN);
        assert!(settings.http);
        assert_eq!(
            settings.hosts_path.as_deref(),
            Some(default_hosts_path().as_path())
        );
        assert_eq!(settings.refresh, Duration::from_secs(30));
    }

    #[test]
    fn merge_no_hosts_disables_sync() {
        let yaml = parse_yaml(
            r#"
hosts: /tmp/hosts
proxies:
  jp: http://127.0.0.1:8080
rules:
  default: jp
"#,
        )
        .unwrap();
        let settings = merge_settings(
            &yaml,
            &CliOverrides {
                no_hosts: true,
                ..CliOverrides::default()
            },
        )
        .unwrap();
        assert!(settings.hosts_path.is_none());
    }

    #[test]
    fn merge_yaml_hosts_false_disables_sync() {
        let yaml = parse_yaml(
            r#"
hosts: false
proxies:
  jp: http://127.0.0.1:8080
rules:
  default: jp
"#,
        )
        .unwrap();
        let settings = merge_settings(&yaml, &CliOverrides::default()).unwrap();
        assert!(settings.hosts_path.is_none());
    }

    #[test]
    fn merge_rejects_non_loopback_listen() {
        let yaml = parse_yaml(sample_yaml()).unwrap();
        let err = merge_settings(
            &yaml,
            &CliOverrides {
                listen: Some("1.1.1.1".parse().unwrap()),
                ..CliOverrides::default()
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("loopback"));
    }

    #[test]
    fn parses_config_source_url_and_file() {
        assert!(matches!(
            ConfigSource::parse("https://example.com/sni.yaml").unwrap(),
            ConfigSource::Url(_)
        ));
        assert!(matches!(
            ConfigSource::parse("./config.yaml").unwrap(),
            ConfigSource::File(_)
        ));
    }

    #[tokio::test]
    async fn fetches_config_from_http() {
        let yaml = sample_yaml();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let body = yaml.to_string();
        tokio::spawn(async move {
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
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let source = ConfigSource::parse(&format!("http://127.0.0.1:{port}/sni.yaml")).unwrap();
        let text = fetch_config(&source, &client).await.unwrap();
        let cfg = parse_yaml(&text).unwrap();
        assert!(cfg.proxies.contains_key("jp"));
    }

    #[tokio::test]
    async fn fetch_rejects_oversized_content_length() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
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
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        });

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let source = ConfigSource::parse(&format!("http://127.0.0.1:{port}/sni.yaml")).unwrap();
        let err = fetch_config_limited(&source, &client, 64)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("larger than 64 bytes"));
    }

    #[tokio::test]
    async fn fetch_rejects_oversized_file() {
        let path = std::env::temp_dir().join(format!(
            "nyasniproxy-config-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, vec![b'a'; 128]).unwrap();
        let client = reqwest::Client::new();
        let source = ConfigSource::File(path.clone());
        let err = fetch_config_limited(&source, &client, 64)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("exceeds 64 bytes"));
        let _ = std::fs::remove_file(&path);
    }
}
