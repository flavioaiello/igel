use serde::Deserialize;

/// Sensor configuration – loaded from a TOML file.
#[derive(Debug, Deserialize)]
pub struct Config {
    /// Opaque identifier burnt into every envelope.
    pub device_id: String,

    /// Seconds between process snapshots.
    #[serde(default = "default_process_interval")]
    pub process_interval: u64,

    /// Seconds between network counter snapshots.
    #[serde(default = "default_network_interval")]
    pub network_interval: u64,

    /// Seconds between baseline checks.
    #[serde(default = "default_baseline_interval")]
    pub baseline_interval: u64,

    /// Seconds between heartbeats.
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval: u64,

    /// Seconds between connection scans.
    #[serde(default = "default_connection_interval")]
    pub connection_interval: u64,

    /// Seconds between listener scans.
    #[serde(default = "default_listener_interval")]
    pub listener_interval: u64,

    /// File paths to watch for integrity changes.
    #[serde(default)]
    pub fim_paths: Vec<String>,

    /// Optional HTTP endpoint for the sink (requires `http` feature).
    #[cfg_attr(not(feature = "http"), allow(dead_code))]
    pub http_url: Option<String>,

    /// Bearer token for HTTP sink authentication.
    #[cfg_attr(not(feature = "http"), allow(dead_code))]
    pub http_auth_token: Option<String>,

    /// Path for event buffer file (disk-backed delivery guarantee).
    #[cfg_attr(not(feature = "http"), allow(dead_code))]
    pub buffer_path: Option<String>,
    pub mqtt_host: Option<String>,
    pub mqtt_sas_token: Option<String>,
}

fn default_process_interval() -> u64 { 60 }
fn default_network_interval() -> u64 { 30 }
fn default_connection_interval() -> u64 { 60 }
fn default_listener_interval() -> u64 { 300 }
fn default_baseline_interval() -> u64 { 3600 }
fn default_heartbeat_interval() -> u64 { 60 }

impl Config {
    /// Load from a TOML file at the given path.
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let cfg: Config = toml::from_str(&text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> anyhow::Result<()> {
        if self.process_interval == 0 { anyhow::bail!("process_interval must be > 0"); }
        if self.network_interval == 0 { anyhow::bail!("network_interval must be > 0"); }
        if self.connection_interval == 0 { anyhow::bail!("connection_interval must be > 0"); }
        if self.listener_interval == 0 { anyhow::bail!("listener_interval must be > 0"); }
        if self.baseline_interval == 0 { anyhow::bail!("baseline_interval must be > 0"); }
        if self.heartbeat_interval == 0 { anyhow::bail!("heartbeat_interval must be > 0"); }
        Ok(())
    }

    /// Parse directly from a TOML string (used by tests).
    #[cfg(test)]
    pub fn from_str(s: &str) -> anyhow::Result<Self> {
        let cfg: Config = toml::from_str(s)?;
        cfg.validate()?;
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_config_uses_defaults() {
        let cfg = Config::from_str(r#"device_id = "test-device""#).expect("parse");
        assert_eq!(cfg.device_id, "test-device");
        assert_eq!(cfg.process_interval, 60);
        assert_eq!(cfg.network_interval, 30);
        assert_eq!(cfg.connection_interval, 60);
        assert_eq!(cfg.listener_interval, 300);
        assert_eq!(cfg.baseline_interval, 3600);
        assert_eq!(cfg.heartbeat_interval, 60);
        assert!(cfg.fim_paths.is_empty());
        assert!(cfg.http_url.is_none());
        assert!(cfg.http_auth_token.is_none());
        assert!(cfg.buffer_path.is_none());
        assert!(cfg.mqtt_host.is_none());
        assert!(cfg.mqtt_sas_token.is_none());
    }

    #[test]
    fn full_config_parses_all_fields() {
        let toml = r#"
            device_id = "sensor-42"
            process_interval = 10
            network_interval = 5
            connection_interval = 15
            listener_interval = 120
            baseline_interval = 1800
            heartbeat_interval = 30
            fim_paths = ["/etc/passwd", "/etc/shadow"]
            http_url = "https://example.com/ingest"
            http_auth_token = "tok-123"
            buffer_path = "/tmp/buf.ndjson"
            mqtt_host = "hub.example.com"
            mqtt_sas_token = "SharedAccessSignature sr=..."
        "#;
        let cfg = Config::from_str(toml).expect("parse");
        assert_eq!(cfg.device_id, "sensor-42");
        assert_eq!(cfg.process_interval, 10);
        assert_eq!(cfg.network_interval, 5);
        assert_eq!(cfg.connection_interval, 15);
        assert_eq!(cfg.listener_interval, 120);
        assert_eq!(cfg.baseline_interval, 1800);
        assert_eq!(cfg.heartbeat_interval, 30);
        assert_eq!(cfg.fim_paths, vec!["/etc/passwd", "/etc/shadow"]);
        assert_eq!(cfg.http_url.as_deref(), Some("https://example.com/ingest"));
        assert_eq!(cfg.http_auth_token.as_deref(), Some("tok-123"));
        assert_eq!(cfg.buffer_path.as_deref(), Some("/tmp/buf.ndjson"));
        assert_eq!(cfg.mqtt_host.as_deref(), Some("hub.example.com"));
    }

    #[test]
    fn missing_device_id_fails() {
        let result = Config::from_str(r#"process_interval = 60"#);
        assert!(result.is_err(), "device_id is required");
    }

    #[test]
    fn load_from_file() {
        let dir = std::env::temp_dir().join("igel_test_config");
        std::fs::create_dir_all(&dir).ok();
        let path = dir.join("test.toml");
        std::fs::write(&path, r#"device_id = "file-test""#).expect("write");
        let cfg = Config::load(path.to_str().expect("path")).expect("load");
        assert_eq!(cfg.device_id, "file-test");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn load_nonexistent_file_fails() {
        let result = Config::load("/tmp/igel_nonexistent_892374.toml");
        assert!(result.is_err());
    }

    #[test]
    fn invalid_toml_fails() {
        let result = Config::from_str("this is not valid toml {{{{");
        assert!(result.is_err());
    }

    #[test]
    fn wrong_type_for_interval_fails() {
        let result = Config::from_str(r#"
            device_id = "test"
            process_interval = "not a number"
        "#);
        assert!(result.is_err());
    }

    #[test]
    fn zero_interval_rejected() {
        let result = Config::from_str(r#"
            device_id = "test"
            process_interval = 0
        "#);
        assert!(result.is_err(), "zero interval must be rejected");
    }
}
