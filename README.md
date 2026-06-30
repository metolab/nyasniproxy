# nyasniproxy

`nyasniproxy` listens on a loopback address and forwards traffic for domains mapped to that address in `hosts`.
It extracts the real destination from HTTP `Host` or TLS SNI, then opens a tunnel through an upstream HTTP,
HTTPS, or SOCKS5 proxy.

## Usage

```sh
cargo build --release
sudo ./target/release/nyasniproxy --listen 127.0.0.2 --proxy socks5://user:pass@127.0.0.1:1080
```

Example `/etc/hosts` entry:

```text
127.0.0.2 example.com www.example.com
```

The program binds `127.0.0.2:80` and `127.0.0.2:443` by default. Binding low ports usually requires
`sudo`. On Linux you can alternatively grant the binary the bind capability:

```sh
sudo setcap cap_net_bind_service=+ep ./target/release/nyasniproxy
```

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
