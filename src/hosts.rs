use std::fs;
use std::net::IpAddr;
use std::path::Path;

use anyhow::{anyhow, Context, Result};

pub(crate) const BEGIN_MARK: &str = "# BEGIN nyasniproxy";
pub(crate) const END_MARK: &str = "# END nyasniproxy";

pub(crate) fn render_block(ip: IpAddr, names: &[String], newline: &str) -> String {
    let mut block = String::new();
    block.push_str(BEGIN_MARK);
    block.push_str(newline);
    if !names.is_empty() {
        block.push_str(&ip.to_string());
        for name in names {
            block.push(' ');
            block.push_str(name);
        }
        block.push_str(newline);
    }
    block.push_str(END_MARK);
    block.push_str(newline);
    block
}

fn skip_eol(text: &str, offset: usize) -> usize {
    let rest = &text[offset..];
    if rest.starts_with("\r\n") {
        offset + 2
    } else if rest.starts_with('\n') {
        offset + 1
    } else {
        offset
    }
}

fn splice(original: &str, start: usize, after: usize, block: &str) -> String {
    let mut out = String::with_capacity(original.len() + block.len());
    out.push_str(&original[..start]);
    out.push_str(block);
    if !block.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&original[after..]);
    out
}

fn append_block(original: &str, block: &str) -> String {
    let mut out = original.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    if !out.is_empty() {
        let newline = if original.contains("\r\n") {
            "\r\n"
        } else {
            "\n"
        };
        out.push_str(newline);
    }
    out.push_str(block);
    if !block.ends_with('\n') {
        out.push('\n');
    }
    out
}

pub(crate) fn replace_managed_block(original: &str, block: &str) -> String {
    match (original.find(BEGIN_MARK), original.find(END_MARK)) {
        (Some(start), Some(end)) if end > start => {
            let after = skip_eol(original, end + END_MARK.len());
            splice(original, start, after, block)
        }
        (Some(start), _) => splice(original, start, original.len(), block),
        _ => append_block(original, block),
    }
}

fn write_atomic(path: &Path, content: &str) -> Result<()> {
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("hosts path has no file name"))?;
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    let tmp = dir.join(format!(".{}.nyasniproxy.tmp", file_name.to_string_lossy()));
    let cleanup = || {
        let _ = fs::remove_file(&tmp);
    };

    if let Err(err) = fs::write(&tmp, content) {
        cleanup();
        return Err(err).with_context(|| format!("write temp hosts {}", tmp.display()));
    }
    if let Ok(meta) = fs::metadata(path) {
        if let Err(err) = fs::set_permissions(&tmp, meta.permissions()) {
            cleanup();
            return Err(err).context("copy hosts permissions");
        }
    }
    match fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(_) => {
            let result =
                fs::write(path, content).with_context(|| format!("write hosts {}", path.display()));
            cleanup();
            result
        }
    }
}

pub(crate) fn sync_hosts(path: &Path, ip: IpAddr, names: &[String]) -> Result<bool> {
    let original =
        fs::read_to_string(path).with_context(|| format!("read hosts {}", path.display()))?;
    let newline = if original.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let block = render_block(ip, names, newline);
    let updated = replace_managed_block(&original, &block);
    if updated == original {
        return Ok(false);
    }
    write_atomic(path, &updated)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "nyasniproxy-hosts-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn seed_hosts(path: &Path) {
        fs::write(path, "127.0.0.1 localhost\n").unwrap();
    }

    #[test]
    fn inserts_block_into_empty_file() {
        let block = render_block("127.0.0.2".parse().unwrap(), &["example.com".into()], "\n");
        let updated = replace_managed_block("", &block);
        assert_eq!(
            updated,
            "# BEGIN nyasniproxy\n127.0.0.2 example.com\n# END nyasniproxy\n"
        );
    }

    #[test]
    fn replaces_existing_block_and_preserves_other_lines() {
        let original = "127.0.0.1 localhost\n# BEGIN nyasniproxy\n127.0.0.2 old.com\n# END nyasniproxy\n# keep me\n";
        let block = render_block(
            "127.0.0.2".parse().unwrap(),
            &["new.com".into(), "www.new.com".into()],
            "\n",
        );
        let updated = replace_managed_block(original, &block);
        assert_eq!(
            updated,
            "127.0.0.1 localhost\n# BEGIN nyasniproxy\n127.0.0.2 new.com www.new.com\n# END nyasniproxy\n# keep me\n"
        );
    }

    #[test]
    fn replaces_from_begin_when_end_mark_is_missing() {
        let original =
            "127.0.0.1 localhost\n# BEGIN nyasniproxy\n127.0.0.2 stale.com\n# leftover\n";
        let block = render_block("127.0.0.2".parse().unwrap(), &["fresh.com".into()], "\n");
        let updated = replace_managed_block(original, &block);
        assert_eq!(
            updated,
            "127.0.0.1 localhost\n# BEGIN nyasniproxy\n127.0.0.2 fresh.com\n# END nyasniproxy\n"
        );
        assert!(!updated.contains("stale.com"));
        assert!(!updated.contains("leftover"));
    }

    #[test]
    fn sync_hosts_writes_then_skips_unchanged() {
        let path = temp_path("sync");
        seed_hosts(&path);
        let ip = "127.0.0.2".parse().unwrap();
        let names = vec!["a.example".to_string(), "b.example".to_string()];
        assert!(sync_hosts(&path, ip, &names).unwrap());
        assert!(!sync_hosts(&path, ip, &names).unwrap());
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("127.0.0.1 localhost"));
        assert!(text.contains("127.0.0.2 a.example b.example"));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn sync_hosts_updates_when_names_change() {
        let path = temp_path("update");
        seed_hosts(&path);
        let ip = "127.0.0.2".parse().unwrap();
        assert!(sync_hosts(&path, ip, &["one.example".into()]).unwrap());
        assert!(sync_hosts(&path, ip, &["two.example".into()]).unwrap());
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("two.example"));
        assert!(!text.contains("one.example"));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn sync_hosts_errors_if_file_is_missing() {
        let path = temp_path("missing");
        let err =
            sync_hosts(&path, "127.0.0.2".parse().unwrap(), &["a.example".into()]).unwrap_err();
        assert!(err.to_string().contains("read hosts"));
    }
}
