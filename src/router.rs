use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use anyhow::{anyhow, bail, Result};
use tracing::warn;

use crate::config::FileConfig;
use crate::proxy::{ProxyConfig, ProxyStream};
use crate::target::{is_valid_hostname, Target};

#[derive(Clone, Debug)]
pub(crate) struct Hop {
    pub(crate) name: String,
    pub(crate) proxy: Arc<ProxyConfig>,
}

#[derive(Debug)]
pub(crate) struct Router {
    rules: HashMap<String, Vec<Hop>>,
    default: Vec<Hop>,
}

impl Router {
    pub(crate) fn lookup(&self, host: &str) -> &[Hop] {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.rules
            .get(&host)
            .map(Vec::as_slice)
            .unwrap_or(&self.default)
    }
}

#[derive(Debug)]
pub(crate) struct Runtime {
    pub(crate) router: Router,
    pub(crate) hostnames: Vec<String>,
    fingerprint: u64,
}

impl Runtime {
    pub(crate) fn from_yaml(yaml: &FileConfig) -> Result<Self> {
        let mut proxies = HashMap::new();
        for (name, url) in &yaml.proxies {
            proxies.insert(name.clone(), Arc::new(ProxyConfig::parse(url)?));
        }

        let resolve = |names: &crate::config::ProxyRef| -> Result<Vec<Hop>> {
            names
                .0
                .iter()
                .map(|name| {
                    let proxy = proxies
                        .get(name)
                        .cloned()
                        .ok_or_else(|| anyhow!("unknown proxy {name}"))?;
                    Ok(Hop {
                        name: name.clone(),
                        proxy,
                    })
                })
                .collect()
        };

        let mut rules = HashMap::new();
        let mut default = None;
        let mut hostnames = Vec::new();
        let mut seen = HashSet::new();

        for (key, names) in &yaml.rules {
            if key.eq_ignore_ascii_case("default") {
                default = Some(resolve(names)?);
                continue;
            }
            if !is_valid_hostname(key) {
                bail!("invalid hostname in rules: {key:?}");
            }
            let hops = resolve(names)?;
            let lower = key.to_ascii_lowercase();
            if seen.insert(lower.clone()) {
                hostnames.push(key.clone());
            }
            rules.insert(lower, hops);
        }

        let default = default.ok_or_else(|| anyhow!("rules.default is required"))?;
        if default.is_empty() {
            bail!("rules.default must not be empty");
        }
        hostnames.sort_by_key(|name| name.to_ascii_lowercase());

        Ok(Self {
            router: Router { rules, default },
            hostnames,
            fingerprint: routing_fingerprint(yaml),
        })
    }

    pub(crate) fn fingerprint(&self) -> u64 {
        self.fingerprint
    }

    #[cfg(test)]
    pub(crate) fn single_proxy(url: &str) -> Result<Self> {
        let proxy = Arc::new(ProxyConfig::parse(url)?);
        Ok(Self {
            router: Router {
                rules: HashMap::new(),
                default: vec![Hop {
                    name: "default".to_string(),
                    proxy,
                }],
            },
            hostnames: Vec::new(),
            fingerprint: 0,
        })
    }
}

pub(crate) fn routing_fingerprint(yaml: &FileConfig) -> u64 {
    let mut hasher = DefaultHasher::new();
    let mut proxies: Vec<_> = yaml.proxies.iter().collect();
    proxies.sort_by(|a, b| a.0.cmp(b.0));
    for (name, url) in proxies {
        name.hash(&mut hasher);
        url.hash(&mut hasher);
    }

    let mut rules: Vec<_> = yaml.rules.iter().collect();
    rules.sort_by(|a, b| a.0.to_ascii_lowercase().cmp(&b.0.to_ascii_lowercase()));
    for (name, hops) in rules {
        name.to_ascii_lowercase().hash(&mut hasher);
        hops.0.hash(&mut hasher);
    }
    hasher.finish()
}

pub(crate) async fn connect_with_fallback(hops: &[Hop], target: &Target) -> Result<ProxyStream> {
    let mut last_err = None;
    for hop in hops {
        match hop.proxy.connect(target).await {
            Ok(stream) => return Ok(stream),
            Err(err) => {
                warn!(node = %hop.name, error = %err, "proxy connect failed, trying fallback");
                last_err = Some(err);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("no proxy candidates")))
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;
    use crate::config::parse_yaml;
    use crate::http::header_end;

    fn sample_yaml() -> FileConfig {
        parse_yaml(
            r#"
proxies:
  jp: http://127.0.0.1:8080
  us: http://127.0.0.1:8081
rules:
  Example.com: us
  www.example.com: [us, jp]
  default: [jp, us]
"#,
        )
        .unwrap()
    }

    #[test]
    fn lookup_is_case_insensitive_and_falls_back_to_default() {
        let runtime = Runtime::from_yaml(&sample_yaml()).unwrap();
        let matched = runtime.router.lookup("EXAMPLE.COM");
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].name, "us");

        let fallback = runtime.router.lookup("www.example.com");
        assert_eq!(
            fallback
                .iter()
                .map(|hop| hop.name.as_str())
                .collect::<Vec<_>>(),
            vec!["us", "jp"]
        );

        let unknown = runtime.router.lookup("other.test.");
        assert_eq!(
            unknown
                .iter()
                .map(|hop| hop.name.as_str())
                .collect::<Vec<_>>(),
            vec!["jp", "us"]
        );
        assert_eq!(runtime.hostnames, vec!["Example.com", "www.example.com"]);
    }

    #[test]
    fn rejects_unknown_proxy_name() {
        let yaml = parse_yaml(
            r#"
proxies:
  jp: http://127.0.0.1:8080
rules:
  default: missing
"#,
        )
        .unwrap();
        let err = Runtime::from_yaml(&yaml).unwrap_err();
        assert!(err.to_string().contains("unknown proxy missing"));
    }

    #[test]
    fn rejects_invalid_rule_hostname() {
        let yaml = parse_yaml(
            r#"
proxies:
  jp: http://127.0.0.1:8080
rules:
  "*.example.com": jp
  default: jp
"#,
        )
        .unwrap();
        let err = Runtime::from_yaml(&yaml).unwrap_err();
        assert!(err.to_string().contains("invalid hostname in rules"));
    }

    #[tokio::test]
    async fn connect_with_fallback_skips_dead_proxy() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
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
            request
        });

        let dead = Arc::new(ProxyConfig::parse("http://127.0.0.1:1").unwrap());
        let live = Arc::new(ProxyConfig::parse(&format!("http://127.0.0.1:{port}")).unwrap());
        let hops = vec![
            Hop {
                name: "dead".to_string(),
                proxy: dead,
            },
            Hop {
                name: "live".to_string(),
                proxy: live,
            },
        ];
        let target = Target {
            host: "example.com".to_string(),
            port: 443,
        };
        let mut tunnel = connect_with_fallback(&hops, &target).await.unwrap();
        tunnel.shutdown().await.unwrap();
        let request = String::from_utf8(server.await.unwrap()).unwrap();
        assert!(request.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
    }
}
