use serde::Deserialize;

const MAX_DEVICE_ID_LEN: usize = 128;
const MAX_FIM_PATHS: usize = 128;
const MAX_PATH_LEN: usize = 4096;
const MAX_ENDPOINT_LEN: usize = 2048;
const MAX_TOKEN_LEN: usize = 4096;

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

    /// Seconds between kernel integrity checks.
    #[serde(default = "default_kernel_interval")]
    pub kernel_interval: u64,

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

    /// Optional path to the hardware watchdog device (e.g., `/dev/watchdog`).
    /// If configured, Igel will periodically pet the watchdog.
    #[serde(default)]
    pub watchdog_path: Option<String>,

    /// If true, proactively lockdowns the kernel on startup.
    #[serde(default)]
    #[allow(dead_code)]
    pub enforce_kernel_lockdown: bool,
}

fn default_process_interval() -> u64 {
    60
}
fn default_network_interval() -> u64 {
    30
}
fn default_connection_interval() -> u64 {
    60
}
fn default_listener_interval() -> u64 {
    300
}
fn default_baseline_interval() -> u64 {
    3600
}
fn default_kernel_interval() -> u64 {
    300
}
fn default_heartbeat_interval() -> u64 {
    60
}

fn validate_optional_token(name: &str, value: Option<&str>) -> anyhow::Result<()> {
    if let Some(token) = value {
        if token.is_empty() || token.len() > MAX_TOKEN_LEN {
            anyhow::bail!("{} must be 1..={} characters", name, MAX_TOKEN_LEN);
        }
        if token.chars().any(char::is_control) {
            anyhow::bail!("{} contains control characters", name);
        }
    }
    Ok(())
}

impl Config {
    /// Load from a TOML file at the given path.
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let cfg: Config = toml::from_str(&text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> anyhow::Result<()> {
        let trimmed_device_id = self.device_id.trim();
        if trimmed_device_id.is_empty() {
            anyhow::bail!("device_id must not be empty");
        }
        if self.device_id.len() > MAX_DEVICE_ID_LEN {
            anyhow::bail!("device_id exceeds {} characters", MAX_DEVICE_ID_LEN);
        }
        if self.device_id.chars().any(char::is_control) {
            anyhow::bail!("device_id contains control characters");
        }

        if self.process_interval == 0 {
            anyhow::bail!("process_interval must be > 0");
        }
        if self.network_interval == 0 {
            anyhow::bail!("network_interval must be > 0");
        }
        if self.connection_interval == 0 {
            anyhow::bail!("connection_interval must be > 0");
        }
        if self.listener_interval == 0 {
            anyhow::bail!("listener_interval must be > 0");
        }
        if self.baseline_interval == 0 {
            anyhow::bail!("baseline_interval must be > 0");
        }
        if self.kernel_interval == 0 {
            anyhow::bail!("kernel_interval must be > 0");
        }
        if self.heartbeat_interval == 0 {
            anyhow::bail!("heartbeat_interval must be > 0");
        }

        if self.fim_paths.len() > MAX_FIM_PATHS {
            anyhow::bail!("fim_paths exceeds {} entries", MAX_FIM_PATHS);
        }
        for path in &self.fim_paths {
            let p = path.trim();
            if p.is_empty() {
                anyhow::bail!("fim_paths entries must not be empty");
            }
            if p.len() > MAX_PATH_LEN {
                anyhow::bail!("fim path exceeds {} characters", MAX_PATH_LEN);
            }
            if p.chars().any(char::is_control) {
                anyhow::bail!("fim path contains control characters");
            }
            if !std::path::Path::new(p).is_absolute() {
                anyhow::bail!("fim path must be absolute: {}", p);
            }
        }

        if let Some(url) = self.http_url.as_deref() {
            if url.is_empty() || url.len() > MAX_ENDPOINT_LEN {
                anyhow::bail!("http_url must be 1..={} characters", MAX_ENDPOINT_LEN);
            }
            if !url.starts_with("https://") {
                anyhow::bail!("http_url must use https://");
            }
            if url.chars().any(char::is_control) {
                anyhow::bail!("http_url contains control characters");
            }
        }
        validate_optional_token("http_auth_token", self.http_auth_token.as_deref())?;

        if let Some(path) = self.buffer_path.as_deref() {
            let p = path.trim();
            if p.is_empty() || p.len() > MAX_PATH_LEN {
                anyhow::bail!("buffer_path must be 1..={} characters", MAX_PATH_LEN);
            }
            if p.chars().any(char::is_control) {
                anyhow::bail!("buffer_path contains control characters");
            }
            if !std::path::Path::new(p).is_absolute() {
                anyhow::bail!("buffer_path must be absolute");
            }
        }

        if let Some(host) = self.mqtt_host.as_deref() {
            if host.is_empty() || host.len() > 255 {
                anyhow::bail!("mqtt_host must be 1..=255 characters");
            }
            if host.chars().any(char::is_control) {
                anyhow::bail!("mqtt_host contains control characters");
            }
        }
        validate_optional_token("mqtt_sas_token", self.mqtt_sas_token.as_deref())?;

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
        let result = Config::from_str(
            r#"
            device_id = "test"
            process_interval = "not a number"
        "#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn zero_interval_rejected() {
        let result = Config::from_str(
            r#"
            device_id = "test"
            process_interval = 0
        "#,
        );
        assert!(result.is_err(), "zero interval must be rejected");
    }

    #[test]
    fn empty_device_id_rejected() {
        let result = Config::from_str(r#"device_id = """#);
        assert!(result.is_err(), "empty device_id must be rejected");
    }

    #[test]
    fn relative_fim_path_rejected() {
        let result = Config::from_str(
            r#"
            device_id = "test"
            fim_paths = ["relative/path"]
        "#,
        );
        assert!(result.is_err(), "relative fim path must be rejected");
    }

    #[test]
    fn too_many_fim_paths_rejected() {
        let mut paths = String::new();
        for i in 0..129 {
            if i > 0 {
                paths.push_str(", ");
            }
            paths.push_str(&format!("\"/tmp/path{}\"", i));
        }
        let cfg = format!("device_id = \"test\"\nfim_paths = [{}]", paths);
        let result = Config::from_str(&cfg);
        assert!(result.is_err(), "excessive fim paths must be rejected");
    }

    #[test]
    fn empty_http_auth_token_rejected() {
        let result = Config::from_str(
            r#"
            device_id = "test"
            http_auth_token = ""
        "#,
        );
        assert!(result.is_err(), "empty HTTP auth token must be rejected");
    }

    #[test]
    fn plaintext_http_url_rejected() {
        let result = Config::from_str(
            r#"
            device_id = "test"
            http_url = "http://example.com/ingest"
        "#,
        );
        assert!(result.is_err(), "plain HTTP sink URLs must be rejected");
    }

    #[test]
    fn mqtt_sas_token_control_character_rejected() {
        let result = Config::from_str(
            r#"
            device_id = "test"
            mqtt_sas_token = "bad\ntoken"
        "#,
        );
        assert!(
            result.is_err(),
            "control characters in MQTT tokens must be rejected"
        );
    }
}
