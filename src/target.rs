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
}
