# Igel 🦔

Tiny, zero-trust security sensor for IoT devices.  
Outputs NDJSON to **stdout** — pipe it to any SIEM, cloud ingestion, or log collector.

## What it collects

| Kind | Description |
|---|---|
| `processes` | Running process snapshot (pid, ppid, name, cmd, user, cpu, mem) |
| `network` | Interface TX/RX byte counters |
| `connections` | Active TCP/UDP connections with PID resolution (Linux) |
| `listeners` | Listening network sockets with PID resolution (Linux) |
| `fim` | File integrity monitoring — push-based via inotify/kqueue (SHA-256 change detection) |
| `baseline` | CIS-style security baseline checks (15 checks, Linux) |
| `tamper` | Tamper detection: ptrace injection, kernel taint, unauthorized RW mounts (Linux) |
| `heartbeat` | System vitals + uptime + event counter |

Every event is wrapped in a uniform `Envelope` with `ts`, `device`, `kind`, and `v` (crate version string).

### Self-protection

On Linux, Igel hardens its own process at startup:

- Disables core dumps via `PR_SET_DUMPABLE` to prevent memory inspection by a local adversary.

### Tamper detection

Each baseline cycle also runs tamper checks:

- **Active ptrace** — detects debuggers/injectors attached to any running process.
- **Kernel taint** — flags unsigned modules, forced module loads, or other kernel integrity violations.
- **Unauthorized RW mounts** — alerts when critical paths (`/`, `/usr`, `/bin`) are mounted read-write.

### Baseline checks (CIS-aligned)

| Category | Check | CIS Ref |
|---|---|---|
| auth | `/etc/shadow` permissions | 6.1.3 |
| auth | `/etc/passwd` permissions | 6.1.2 |
| auth | Password max age ≤ 90 days | 5.4.1.1 |
| auth | SSH `PermitRootLogin no` | 5.2.10 |
| auth | SSH `MaxAuthTries` ≤ 4 | 5.2.7 |
| auth | SSH `PermitEmptyPasswords no` | 5.2.11 |
| network | IP forwarding disabled | 3.1.1 |
| network | TCP SYN cookies enabled | 3.2.8 |
| network | ICMP redirects disabled | 3.2.2 |
| network | Source routing disabled | 3.2.1 |
| system | ASLR enabled (level 2) | 1.5.3 |
| system | Core dumps restricted | 1.5.1 |
| filesystem | No world-writable files in `/etc` | — |
| filesystem | `/tmp` mounted `noexec` | 1.1.2–1.1.5 |
| filesystem | `/tmp` mounted `nosuid` | 1.1.2–1.1.5 |

## Build

```sh
cargo build --release                    # stdout-only, ~1 MB stripped
cargo build --release --features http    # + HTTP POST sink
cargo build --release --features mqtt    # + MQTT sink (Azure IoT Hub)
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

The Dockerfile uses a two-stage Alpine/musl build for a minimal image.

## Configuration

Create `/etc/igel/igel.toml` (or pass the path as the first argument):

```toml
device_id = "sensor-42"

process_interval   = 60    # seconds (default: 60)
network_interval   = 30    # default: 30
connection_interval = 60   # default: 60
listener_interval  = 300   # default: 300
baseline_interval  = 3600  # default: 3600
heartbeat_interval = 60    # default: 60

# FIM is push-based (inotify/kqueue) — no polling interval needed.
fim_paths = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/ssh/sshd_config",
]

# Requires `--features http`
# http_url = "https://ingest.example.com/v1/events"
# http_auth_token = "your-bearer-token-here"
# buffer_path = "/var/lib/igel/buffer.ndjson"

# Requires `--features mqtt`
# mqtt_host = "your-hub.azure-devices.net"
# mqtt_sas_token = "SharedAccessSignature ..."
```

## Sinks

| Sink | Feature flag | Transport |
|---|---|---|
| **stdout** | *(default)* | NDJSON to stdout — pipe to any consumer |
| **HTTP** | `http` | POST to any HTTP endpoint with optional Bearer auth and disk-backed buffer |
| **MQTT** | `mqtt` | Azure IoT Hub via MQTT 3.1.1 over TLS (native root certs) |

Only one sink is active per build. If no endpoint is configured, the sink falls back to stdout.

## Run

```sh
# Stdout (default) – pipe to anything:
igel /etc/igel/igel.toml | tee /var/log/igel.ndjson

# Forward to Fluent Bit / Vector / Logstash / Defender for Cloud:
igel | fluent-bit -i stdin -o azure_logs_ingestion ...
```

## Output format

Every line is a self-contained JSON object. Payload fields are flattened into the envelope:

```json
{"ts":"2025-01-15T10:30:00Z","device":"sensor-42","kind":"processes","v":"0.1.0","pid":1,"ppid":null,"name":"init","cmd":"/sbin/init","user":"root","cpu":0.1,"mem_bytes":4096}
```

## License

MIT
