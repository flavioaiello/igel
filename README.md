# Igel 🦔

Tiny, zero-trust security sensor for IoT devices.  
Outputs NDJSON to **stdout** — pipe it to any SIEM, cloud ingestion, or log collector.

## Why Igel

Most security agents are built for servers and desktops — they assume gigabytes of RAM, fast disks, and a fat runtime. IoT and OT devices get none of that. Igel exists because constrained devices still deserve real security telemetry, not a watered-down afterthought.

**One static binary, nothing else.** No Python, no JVM, no container runtime required. Igel compiles to a single musl-linked binary under 1 MB. It cross-compiles to ARM in one command and runs on anything from a Raspberry Pi to an industrial gateway.

**Security sensor that secures itself.** Igel disables its own core dumps, restricts ptrace attachment, and applies an irrevocable Landlock filesystem sandbox — all before emitting a single event. If the device is compromised, the sensor is hardened against inspection and tampering.

**Pipe-native, vendor-neutral.** Every event is one line of NDJSON on stdout. Pipe it to Fluent Bit, Vector, Logstash, a cloud API, or a plain file. Switch SIEMs without touching the sensor. Optional HTTP and MQTT sinks are available when stdout isn't enough.

**Push-based file integrity.** FIM uses inotify/kqueue — changes are detected the instant they happen, not on the next polling cycle. No wasted CPU spinning over unchanged files.

**CIS baselines and tamper detection included.** Fifteen CIS-aligned checks (SSH hardening, ASLR, mount options, kernel parameters) and active tamper signals (ptrace injection, kernel taint, unauthorized read-write mounts) ship out of the box. No plugins, no policy downloads.

**Built for the long tail.** Single-threaded async runtime, bounded allocations, zero-copy serialization where possible. Igel is designed to run for months on a device with 64 MB of RAM without drifting upward.

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

## Azure integration

Igel is designed to feed directly into the Azure IoT security stack. The MQTT sink speaks Azure IoT Hub's native protocol — no gateway, agent framework, or SDK required.

### How it connects

The `mqtt` feature compiles in a lightweight MQTT 3.1.1 client that connects to Azure IoT Hub over TLS (port 8883). Authentication uses a **SAS token** tied to the device identity. TLS is handled by `rustls` with platform-native root certificates — no OpenSSL dependency and no certificate bundles to ship.

```
Igel ──MQTT/TLS──▶ Azure IoT Hub ──message routing──▶ ┬─ Microsoft Sentinel
                                                       ├─ Microsoft Defender for IoT
                                                       ├─ Log Analytics / ADX
                                                       └─ Event Hubs / Storage
```

Every NDJSON event is published to `devices/{device_id}/messages/events/` with QoS 1 (at-least-once delivery). IoT Hub message routing can then fan out events by `kind` to different endpoints — for example, `tamper` and `baseline` events to Sentinel for alerting, `heartbeat` events to a storage account for fleet health dashboards.

### Configuration

```toml
device_id  = "sensor-42"
mqtt_host  = "your-hub.azure-devices.net"
mqtt_sas_token = "SharedAccessSignature sr=your-hub..."
```

Generate a SAS token with the Azure CLI:

```sh
az iot hub generate-sas-token -d sensor-42 -n your-hub --duration 31536000
```

### Downstream routing

| Azure service | Use case |
|---|---|
| **Microsoft Defender for IoT** | Correlate Igel telemetry with network-layer anomaly detection for unified IoT/OT threat visibility |
| **Microsoft Sentinel** | Ingest events into Sentinel workspaces for KQL-based detection rules, workbooks, and SOAR playbooks |
| **Log Analytics / ADX** | Long-term retention, fleet-wide queries, compliance reporting |
| **Event Hubs** | Real-time stream processing for custom alerting pipelines or third-party SIEM forwarding |

### Stdout-to-Azure alternatives

When MQTT is not available (air-gapped networks, legacy devices), pipe stdout through a local forwarder:

```sh
# Fluent Bit → Azure Log Analytics
igel /etc/igel/igel.toml | fluent-bit -i stdin -o azure_logs_ingestion ...

# Fluent Bit → Azure Event Hubs
igel /etc/igel/igel.toml | fluent-bit -i stdin -o azure_blob ...
```

## MITRE ATT&CK detections

Igel's telemetry maps to concrete MITRE ATT&CK techniques relevant to IoT and OT device compromise. Every detection listed below is produced by the sensor out of the box — no additional rules or plugins needed.

Ready-to-deploy **Microsoft Sentinel analytic rules** (KQL) for every detection below are in [`sentinel/`](sentinel/). See the [deployment guide](sentinel/README.md) for import instructions.

### Process telemetry → Execution & Persistence

| Technique | ID | Igel signal |
|---|---|---|
| Command and Scripting Interpreter | T1059 | Process snapshots surface unexpected interpreters (`python`, `sh`, `perl`, `lua`) running on a headless device |
| Create or Modify System Process | T1543 | New persistent daemons detected by diffing successive process snapshots across cycles |
| Scheduled Task/Job | T1053 | Process tree reveals `cron`, `at`, or `systemd-run` invocations that should not exist on a locked-down device |

### Connection & listener telemetry → Command and Control

| Technique | ID | Igel signal |
|---|---|---|
| Application Layer Protocol | T1071 | Active connections expose outbound HTTP/DNS/MQTT sessions to unexpected destinations |
| Non-Standard Port | T1571 | Connections on unusual ports (e.g. high-port outbound TCP) are visible with PID resolution |
| Proxy / Tunneling | T1090 | Unexpected SOCKS or SSH tunnels appear as listening sockets with foreign remote endpoints |
| Remote Services | T1021 | Listener events reveal unauthorized SSH, VNC, or Telnet daemons opened post-deployment |
| Non-Application Layer Protocol | T1095 | Raw UDP/TCP sockets opened by unknown PIDs indicate potential covert channels |

### File integrity monitoring → Impact & Persistence

| Technique | ID | Igel signal |
|---|---|---|
| Stored Data Manipulation | T1565.001 | FIM detects modification of configuration files, firmware images, or application binaries |
| Account Manipulation | T1098 | Changes to `/etc/passwd` or `/etc/shadow` trigger immediate FIM events with before/after hashes |
| Hijack Execution Flow | T1574 | Modifications to shared libraries or `LD_PRELOAD` config files are caught in real time |
| Boot or Logon Autostart Execution | T1547 | FIM on `/etc/rc.local`, systemd unit directories, or init scripts detects persistence implants |

### Baseline checks → Defense Evasion & Credential Access

| Technique | ID | Igel signal |
|---|---|---|
| Modify Authentication Process | T1556 | SSH hardening checks detect loosened `PermitRootLogin`, `MaxAuthTries`, or `PermitEmptyPasswords` |
| Abuse Elevation Control Mechanism | T1548 | ASLR level, core dump policy, and `noexec`/`nosuid` mount enforcement detect weakened exploit mitigations |
| Impair Defenses | T1562 | Baseline drift (IP forwarding enabled, SYN cookies disabled, source routing allowed) reveals defense degradation |
| Unsecured Credentials | T1552 | File permission checks on `/etc/shadow` and `/etc/passwd` detect credential exposure |

### Tamper detection → Privilege Escalation & Defense Evasion

| Technique | ID | Igel signal |
|---|---|---|
| Process Injection | T1055 | Active ptrace scan detects debuggers or injectors attached to any running process |
| Rootkit | T1014 | Kernel taint flag detects unsigned module loads, forced insmod, or other kernel integrity violations |
| Direct Volume Access | T1006 | Unauthorized read-write mounts on `/`, `/usr`, `/bin` indicate filesystem tamper attempts |

### Heartbeat → Collection & Sensor health

| Technique | ID | Igel signal |
|---|---|---|
| Disable or Modify Tools | T1562.001 | Missing heartbeats in the SIEM indicate the sensor has been killed, blocked, or starved of resources |
| Resource Hijacking | T1496 | CPU and memory metrics in heartbeat events detect cryptominers or resource-abuse malware |

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
