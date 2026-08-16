use anyhow::{bail, Context, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Target {
    pub(crate) host: String,
    pub(crate) port: u16,
}

pub(crate) fn parse_host_port(value: &str, default_port: u16) -> Result<Target> {
    if value.is_empty() {
        bail!("empty host");
    }

    if let Some(host) = value.strip_prefix('[') {
        let Some((host, rest)) = host.split_once(']') else {
            bail!("invalid bracketed IPv6 host");
        };
        let port = if let Some(port) = rest.strip_prefix(':') {
            port.parse().context("invalid port")?
        } else if rest.is_empty() {
            default_port
        } else {
            bail!("invalid bracketed host suffix");
        };
        return Ok(Target {
            host: host.to_string(),
            port,
        });
    }

    if let Some((host, port)) = value.rsplit_once(':') {
        if !host.contains(':') && !port.is_empty() {
            return Ok(Target {
                host: host.to_string(),
                port: port.parse().context("invalid port")?,
            });
        }
    }

    Ok(Target {
        host: value.to_string(),
        port: default_port,
    })
}

pub(crate) fn format_target(target: &Target) -> String {
    if target.host.contains(':') && !target.host.starts_with('[') {
        format!("[{}]:{}", target.host, target.port)
    } else {
        format!("{}:{}", target.host, target.port)
    }
}

pub(crate) fn is_valid_hostname(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 || host.starts_with('.') || host.ends_with('.') {
        return false;
    }
    host.split('.').all(is_valid_dns_label)
}

fn is_valid_dns_label(label: &str) -> bool {
    let len = label.len();
    if len == 0 || len > 63 {
        return false;
    }
    let bytes = label.as_bytes();
    bytes[0].is_ascii_alphanumeric()
        && bytes[len - 1].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_host_with_default_port() {
        let target = parse_host_port("example.com", 80).unwrap();
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, 80);
    }

    #[test]
    fn parses_host_with_explicit_port() {
        let target = parse_host_port("example.com:8443", 80).unwrap();
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, 8443);
    }

    #[test]
    fn parses_bracketed_ipv6_with_port() {
        let target = parse_host_port("[::1]:443", 80).unwrap();
        assert_eq!(target.host, "::1");
        assert_eq!(target.port, 443);
        assert_eq!(format_target(&target), "[::1]:443");
    }

    #[test]
    fn rejects_empty_host() {
        assert!(parse_host_port("", 80).is_err());
    }

    #[test]
    fn hostname_validation_accepts_dns_names() {
        assert!(is_valid_hostname("localhost"));
        assert!(is_valid_hostname("example.com"));
        assert!(is_valid_hostname("www.example.com"));
        assert!(is_valid_hostname("xn--fsq.com"));
        assert!(is_valid_hostname("a-b.example"));
    }

    #[test]
    fn hostname_validation_rejects_injection_and_wildcards() {
        assert!(!is_valid_hostname(""));
        assert!(!is_valid_hostname("example.com."));
        assert!(!is_valid_hostname("*.example.com"));
        assert!(!is_valid_hostname("foo.com\n1.2.3.4 google.com"));
        assert!(!is_valid_hostname("foo.com google.com"));
        assert!(!is_valid_hostname("foo.com#comment"));
        assert!(!is_valid_hostname("-bad.com"));
        assert!(!is_valid_hostname("bad-.com"));
    }
}
