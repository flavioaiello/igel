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

// ── Connection events ─────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ConnectionEvent {
    pub protocol: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: String,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
}

// ── Listener events ──────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ListenerEvent {
    pub protocol: String,
    pub addr: String,
    pub port: u16,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn envelope_contains_required_fields() {
        let data = ProcessEvent {
            pid: 1,
            ppid: None,
            name: "init".into(),
            cmd: "/sbin/init".into(),
            user: "root".into(),
            cpu: 0.5,
            mem_bytes: 4096,
        };
        let env = Envelope::new("sensor-01", "processes", data);
        let json = serde_json::to_value(&env).expect("serialize");

        assert_eq!(json["device"], "sensor-01");
        assert_eq!(json["kind"], "processes");
        assert_eq!(json["v"], env!("CARGO_PKG_VERSION"));
        assert!(json["ts"].is_string(), "ts must be an ISO-8601 string");
    }

    #[test]
    fn envelope_payload_is_flattened() {
        let data = NetworkEvent {
            iface: "eth0".into(),
            tx_bytes: 100,
            rx_bytes: 200,
        };
        let env = Envelope::new("sensor-01", "network", data);
        let json = serde_json::to_value(&env).expect("serialize");

        // Flattened: payload fields live at root, not under a "data" key
        assert!(json.get("data").is_none(), "data key must not exist (flattened)");
        assert_eq!(json["iface"], "eth0");
        assert_eq!(json["tx_bytes"], 100);
        assert_eq!(json["rx_bytes"], 200);
    }

    #[test]
    fn envelope_serializes_to_valid_ndjson_line() {
        let data = Heartbeat {
            os: "Linux".into(),
            os_version: "5.15".into(),
            uptime_secs: 3600,
            cpu: 12.5,
            mem_pct: 45.0,
            events_sent: 42,
        };
        let env = Envelope::new("dev-1", "heartbeat", data);
        let line = serde_json::to_string(&env).expect("serialize");

        // Must be a single line (NDJSON requirement)
        assert!(!line.contains('\n'), "NDJSON line must not contain newlines");

        // Must parse back as valid JSON
        let parsed: Value = serde_json::from_str(&line).expect("parse");
        assert_eq!(parsed["kind"], "heartbeat");
        assert_eq!(parsed["uptime_secs"], 3600);
        assert_eq!(parsed["events_sent"], 42);
    }

    #[test]
    fn process_event_serializes_optional_ppid() {
        let with_parent = ProcessEvent {
            pid: 100,
            ppid: Some(1),
            name: "bash".into(),
            cmd: "/bin/bash".into(),
            user: "user".into(),
            cpu: 0.0,
            mem_bytes: 0,
        };
        let without_parent = ProcessEvent {
            pid: 1,
            ppid: None,
            name: "init".into(),
            cmd: "/sbin/init".into(),
            user: "root".into(),
            cpu: 0.0,
            mem_bytes: 0,
        };

        let v1 = serde_json::to_value(&with_parent).expect("serialize");
        let v2 = serde_json::to_value(&without_parent).expect("serialize");

        assert_eq!(v1["ppid"], 1);
        assert!(v2["ppid"].is_null());
    }

    #[test]
    fn fim_event_change_variants() {
        for change in &["created", "modified", "deleted"] {
            let ev = FimEvent {
                path: "/etc/passwd".into(),
                sha256: "abc123".into(),
                prev_sha256: Some("def456".into()),
                change,
                size: 1024,
            };
            let v = serde_json::to_value(&ev).expect("serialize");
            assert_eq!(v["change"], *change);
        }
    }

    #[test]
    fn baseline_event_severity_values() {
        for sev in &["low", "medium", "high", "critical"] {
            let ev = BaselineEvent {
                check: "test".into(),
                category: "test".into(),
                pass: true,
                detail: "ok".into(),
                severity: sev,
            };
            let v = serde_json::to_value(&ev).expect("serialize");
            assert_eq!(v["severity"], *sev);
        }
    }

    #[test]
    fn connection_event_fields() {
        let ev = ConnectionEvent {
            protocol: "tcp".into(),
            local_addr: "127.0.0.1".into(),
            local_port: 8080,
            remote_addr: "10.0.0.1".into(),
            remote_port: 443,
            state: "ESTABLISHED".into(),
            pid: Some(1234),
            process_name: Some("curl".into()),
        };
        let v = serde_json::to_value(&ev).expect("serialize");
        assert_eq!(v["protocol"], "tcp");
        assert_eq!(v["local_port"], 8080);
        assert_eq!(v["pid"], 1234);
        assert_eq!(v["process_name"], "curl");
    }

    #[test]
    fn listener_event_fields() {
        let ev = ListenerEvent {
            protocol: "tcp6".into(),
            addr: "::".into(),
            port: 22,
            pid: None,
            process_name: None,
        };
        let v = serde_json::to_value(&ev).expect("serialize");
        assert_eq!(v["protocol"], "tcp6");
        assert_eq!(v["port"], 22);
        assert!(v["pid"].is_null());
    }
}
