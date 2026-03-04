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

    /// Seconds between FIM checks.
    #[serde(default = "default_fim_interval")]
    pub fim_interval: u64,

    /// Seconds between baseline checks.
    #[serde(default = "default_baseline_interval")]
    pub baseline_interval: u64,

    /// Seconds between heartbeats.
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval: u64,

    /// File paths to watch for integrity changes.
    #[serde(default)]
    pub fim_paths: Vec<String>,

    /// Optional HTTP endpoint for the sink (requires `http` feature).
    #[cfg_attr(not(feature = "http"), allow(dead_code))]
    pub http_url: Option<String>,
}

fn default_process_interval() -> u64 { 60 }
fn default_network_interval() -> u64 { 30 }
fn default_fim_interval() -> u64 { 300 }
fn default_baseline_interval() -> u64 { 3600 }
fn default_heartbeat_interval() -> u64 { 60 }

impl Config {
    /// Load from a TOML file at the given path.
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let text = std::fs::read_to_string(path)?;
        let cfg: Config = toml::from_str(&text)?;
        Ok(cfg)
    }
}
