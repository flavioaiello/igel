# Igel 🦔

Tiny, zero-trust security sensor for IoT devices.  
Outputs NDJSON to **stdout** — pipe it to any SIEM, cloud ingestion, or log collector.

## What it collects

| Kind | Description |
|---|---|
| `process` | Running process snapshot (pid, ppid, name, cmd, user, cpu, mem) |
| `network` | Interface TX/RX byte counters |
| `fim` | File integrity monitoring (SHA-256 change detection) |
| `baseline` | CIS-style security baseline checks |
| `heartbeat` | System vitals + uptime + event counter |

Every event is wrapped in a uniform `Envelope` with `ts`, `device`, `kind`, and `v` (schema version).

## Build

```sh
cargo build --release          # stdout-only, ~1 MB stripped
cargo build --release --features http   # + HTTP POST sink
```

The release profile is tuned for binary size (`opt-level=z`, LTO, strip, `panic=abort`).

### Cross-compile

```sh
# Example: ARM target for Raspberry Pi
rustup target add armv7-unknown-linux-musleabihf
cargo build --release --target armv7-unknown-linux-musleabihf
```

### Container

```sh
docker build -t igel .
docker run -v /path/to/igel.toml:/etc/igel/igel.toml igel
```

## Configuration

Create `/etc/igel/igel.toml` (or pass the path as the first argument):

```toml
device_id = "sensor-42"

process_interval  = 60    # seconds
network_interval  = 30
fim_interval      = 300
baseline_interval = 3600
heartbeat_interval = 60

fim_paths = [
    "/etc/passwd",
    "/etc/shadow",
    "/usr/local/bin/myapp",
]

# Requires `--features http`
# http_url = "https://ingest.example.com/v1/events"
```

## Run

```sh
# Stdout (default) – pipe to anything:
igel /etc/igel/igel.toml | tee /var/log/igel.ndjson

# Forward to Fluent Bit / Vector / Logstash / Defender for Cloud:
igel | fluent-bit -i stdin -o azure_logs_ingestion ...
```

## Output format

```json
{"ts":"2025-01-15T10:30:00Z","device":"sensor-42","kind":"process","v":1,"pid":1,"ppid":null,"name":"init","cmd":"/sbin/init","user":"root","cpu":0.1,"mem_bytes":4096}
```

## License

MIT
