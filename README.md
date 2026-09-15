# nyasniproxy

`nyasniproxy` listens on a loopback address and forwards traffic for domains mapped to that address in `hosts`.
It extracts the real destination from HTTP `Host` or TLS SNI, then opens a tunnel through an upstream HTTP,
HTTPS, or SOCKS5 proxy.

Configuration is a YAML file (local path or HTTP(S) URL) with multiple proxies, per-host routing, fallback,
and a default route. The program can keep a managed block in the hosts file in sync and reload routing when
the config file changes or a remote URL is refreshed.

## Usage

```sh
cargo build --release
sudo ./target/release/nyasniproxy --config ./config.yaml
sudo ./target/release/nyasniproxy --config https://example.com/sni.yaml --listen 127.0.0.2 --refresh 30
sudo ./target/release/nyasniproxy --config ./config.yaml --no-http --hosts /etc/hosts
```

CLI flags override YAML. Precedence is **CLI > YAML > built-in defaults**.

- `--config`: local YAML path or HTTP(S) URL (required)
- `--listen`: loopback listen address (default `127.0.0.2`)
- `--hosts`: hosts file path (Unix default `/etc/hosts`, Windows system hosts)
- `--no-hosts`: disable hosts file sync
- `--no-http`: disable the HTTP listener on port 80
- `--refresh`: remote config poll interval in seconds (default `30`)
- `--log-level`: log filter (default `info`)

The program binds `LISTEN:80` and `LISTEN:443` by default. Binding low ports usually requires `sudo`.
On Linux you can alternatively grant the binary the bind capability:

```sh
sudo setcap cap_net_bind_service=+ep ./target/release/nyasniproxy
```

Writing `/etc/hosts` also needs permission to that file.

## Config

```yaml
proxies:
  jp: http://user:pass@1.2.3.4:8080
  us: http://user:pass@5.6.7.8:8080
  backup: http://127.0.0.1:8081

rules:
  netflix.com: us
  www.netflix.com: [us, jp]
  default: [jp, backup]
```

Optional YAML fields (overridden by CLI when set):

```yaml
listen: 127.0.0.2
hosts: /etc/hosts    # or false to disable sync
refresh: 30
http: true
```

`rules` values are a proxy name or a fallback list tried in order. Matching is exact and case-insensitive.
Hostnames must be valid DNS names (no wildcards or whitespace). `default` is required and is used for unknown Host/SNI values.

Local files are watched and reloaded on change. HTTP(S) URLs are polled every `--refresh` seconds (default 30).
Invalid reloads keep the last good routing table. `listen`, HTTP enablement, hosts path, and refresh are applied
at startup; later YAML changes to those fields are ignored until restart.

Remote fetches (including DNS) run on a dedicated thread with a **15s hard timeout** so a hung
`getaddrinfo` cannot stall accept. Each poll logs one of `config poll completed`, `config poll failed`,
or `config poll skipped` at info/warn/error (visible at the default `--log-level info`).
`--refresh` should be ≥ 15s; shorter values are allowed but will skip while a previous fetch is still
in flight.

If the accept loop stops being polled for **30s**, the process `_exit(1)`s so a supervisor such as
launchd KeepAlive can restart it. KeepAlive must treat a non-zero exit as a restart
(boolean `KeepAlive` or `KeepAlive.SuccessfulExit = false`). Do not put the config URL hostname in
the managed hosts block, or config fetches will hairpin through the proxy.

## Hosts sync

The program maintains a managed block and leaves the rest of the file unchanged:

```text
# BEGIN nyasniproxy
127.0.0.2 netflix.com www.netflix.com
# END nyasniproxy
```

Hostnames come from `rules` except `default`. The address is the listen IP. Disable with `--no-hosts` or `hosts: false`.

## Proxy URLs

Supported upstream proxy schemes:

- `http://host:port`
- `https://host:port`
- `socks5://host:port`
- `http://user:pass@host:port`
- `https://user:pass@host:port`
- `socks5://user:pass@host:port`

HTTPS traffic is not decrypted. The program only peeks at the TLS ClientHello to read SNI, then forwards
the original bytes unchanged.

## Build Targets

```sh
cargo build --release --target x86_64-unknown-linux-gnu
cargo build --release --target aarch64-apple-darwin
```
