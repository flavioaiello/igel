use chrono::{DateTime, Utc};
use serde::Serialize;

// ── Envelope ─────────────────────────────────────────────────────────
// Every event is wrapped in a typed envelope so consumers can
// demultiplex a single NDJSON stream by `kind`.

#[derive(Debug, Serialize)]
pub struct Envelope<T: Serialize> {
    /// ISO-8601 timestamp
    pub ts: DateTime<Utc>,
    /// Device identifier (hostname or configured ID)
    pub device: String,
    /// Event kind discriminator
    pub kind: &'static str,
    /// Sensor version
    pub v: &'static str,
    /// Payload
    #[serde(flatten)]
    pub data: T,
}

impl<T: Serialize> Envelope<T> {
    pub fn new(device: &str, kind: &'static str, data: T) -> Self {
        Self {
            ts: Utc::now(),
            device: device.to_string(),
            kind,
            v: env!("CARGO_PKG_VERSION"),
            data,
        }
    }
}

// ── Process events ───────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ProcessEvent {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub name: String,
    pub cmd: String,
    pub user: String,
    pub cpu: f32,
    pub mem_bytes: u64,
}

// ── Network events ───────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct NetworkEvent {
    pub iface: String,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

// ── File integrity events ────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct FimEvent {
    pub path: String,
    pub sha256: String,
    pub prev_sha256: Option<String>,
    pub change: &'static str, // "created" | "modified" | "deleted"
    pub size: u64,
}

// ── Baseline check events ────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct BaselineEvent {
    pub check: String,
    pub category: String,
    pub pass: bool,
    pub detail: String,
    pub severity: &'static str, // "low" | "medium" | "high" | "critical"
}

// ── Heartbeat ────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct Heartbeat {
    pub os: String,
    pub os_version: String,
    pub uptime_secs: u64,
    pub cpu: f32,
    pub mem_pct: f32,
    pub events_sent: u64,
}
