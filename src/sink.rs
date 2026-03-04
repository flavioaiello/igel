// src/sink.rs
/// Abstraction over output destination.
/// Takes ownership of the serialized JSON line to enable zero-copy
/// forwarding into async tasks (HTTP/MQTT) without an extra `.to_vec()`.
pub trait Sink {
    fn emit(&self, json: Vec<u8>);
}

// ── Stdout (default) ─────────────────────────────────────────────

/// Writes NDJSON to stdout – zero config, pipeable to any consumer.
pub struct StdoutSink;

impl Sink for StdoutSink {
    fn emit(&self, json: Vec<u8>) {
        use std::io::Write;
        let stdout = std::io::stdout();
        let mut lock = stdout.lock();
        if lock.write_all(&json).is_err() || lock.write_all(b"\n").is_err() {
            tracing::error!("stdout write failed");
        }
    }
}

// ── HTTP sink ────────────────────────────────────────────────────

#[cfg(feature = "http")]
use tracing::{debug, error};

#[cfg(feature = "http")]
pub struct HttpSink {
    client: reqwest::Client,
    url: String,
    /// Pre-computed "Bearer <token>" header value — avoids `format!` per request.
    auth_header: Option<String>,
    buffer_path: Option<String>,
    inflight: std::sync::Arc<tokio::sync::Semaphore>,
}

#[cfg(feature = "http")]
/// Maximum concurrent inflight HTTP POST requests.
const MAX_HTTP_INFLIGHT: usize = 16;

#[cfg(feature = "http")]
impl HttpSink {
    pub fn new(url: String, auth_token: Option<String>, buffer_path: Option<String>) -> Self {
        let auth_header = auth_token.map(|t| format!("Bearer {}", t));
        Self {
            client: reqwest::Client::new(),
            url,
            auth_header,
            buffer_path,
            inflight: std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_HTTP_INFLIGHT)),
        }
    }
}

/// Append a failed event to the on-disk buffer for later retry.
#[cfg(feature = "http")]
fn buffer_event(path: &str, json: &[u8]) {
    use std::io::Write;
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        Ok(mut f) => {
            let _ = f.write_all(json);
            let _ = f.write_all(b"\n");
        }
        Err(e) => error!("buffer write: {}", e),
    }
}

#[cfg(feature = "http")]
impl Sink for HttpSink {
    fn emit(&self, json: Vec<u8>) {
        let permit = match self.inflight.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!("http sink: at capacity, buffering event");
                if let Some(ref path) = self.buffer_path {
                    buffer_event(path, &json);
                }
                return;
            }
        };

        let url = self.url.clone();
        let client = self.client.clone();
        let auth_header = self.auth_header.clone();
        let buffer_path = self.buffer_path.clone();

        tokio::spawn(async move {
            let _permit = permit;
            let mut req = client
                .post(&url)
                .header("content-type", "application/json");

            if let Some(ref header_val) = auth_header {
                req = req.header("authorization", header_val.as_str());
            }

            match req.body(json.clone()).send().await {
                Ok(resp) if resp.status().is_success() => {
                    debug!(status = resp.status().as_u16(), "http sink");
                }
                Ok(resp) => {
                    error!(status = resp.status().as_u16(), "http sink non-2xx");
                    if let Some(ref path) = buffer_path {
                        buffer_event(path, &json);
                    }
                }
                Err(e) => {
                    error!(err = %e, "http sink");
                    if let Some(ref path) = buffer_path {
                        buffer_event(path, &json);
                    }
                }
            }
        });
    }
}

/// Drain buffered events, posting them to the HTTP endpoint.
/// Returns the number of events successfully delivered.
/// Stops on first failure to preserve ordering and avoid data loss.
#[cfg(feature = "http")]
pub async fn drain_buffer(url: &str, auth_token: Option<&str>, buffer_path: &str) -> usize {
    let content = match tokio::fs::read_to_string(buffer_path).await {
        Ok(c) if !c.is_empty() => c,
        _ => return 0,
    };

    let client = reqwest::Client::new();
    let lines: Vec<&str> = content.lines().filter(|l| !l.is_empty()).collect();
    let total = lines.len();

    for line in &lines {
        let mut req = client
            .post(url)
            .header("content-type", "application/json");
        if let Some(token) = auth_token {
            req = req.header("authorization", format!("Bearer {}", token));
        }
        match req.body(line.to_string()).send().await {
            Ok(resp) if resp.status().is_success() => {}
            _ => return 0, // abort drain on first failure — retry next cycle
        }
    }

    // All events delivered; truncate buffer
    let _ = tokio::fs::write(buffer_path, b"").await;
    total
}

// ── MQTT sink ──

#[cfg(feature = "mqtt")]
/// Maximum concurrent inflight MQTT publish tasks.
const MAX_MQTT_INFLIGHT: usize = 32;

#[cfg(feature = "mqtt")]
pub struct MqttSink {
    client: rumqttc::AsyncClient,
    /// Pre-computed MQTT topic — avoids `format!` allocation on every publish.
    topic: String,
    inflight: std::sync::Arc<tokio::sync::Semaphore>,
}

#[cfg(feature = "mqtt")]
impl MqttSink {
    pub fn new(host: String, device_id: String, sas_token: Option<String>) -> anyhow::Result<Self> {
        let mut mqttoptions = rumqttc::MqttOptions::new(
            &device_id,
            host.as_str(),
            8883,
        );
        mqttoptions.set_keep_alive(std::time::Duration::from_secs(30));

        if let Some(token) = sas_token {
            mqttoptions.set_credentials(
                format!("{}/{}/?api-version=2020-09-30", host, device_id),
                token,
            );
        }

        let mut root_store = rustls::RootCertStore::empty();
        let cert_result = rustls_native_certs::load_native_certs();
        for e in &cert_result.errors {
            tracing::warn!("error loading platform certificate: {e}");
        }
        if cert_result.certs.is_empty() {
            anyhow::bail!("no platform TLS certificates found");
        }
        for cert in cert_result.certs {
            if let Err(e) = root_store.add(cert) {
                tracing::warn!("skipping malformed root certificate: {e}");
            }
        }

        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        mqttoptions.set_transport(rumqttc::Transport::tls_with_config(client_config.into()));
        let (client, mut eventloop) = rumqttc::AsyncClient::new(mqttoptions, 100);

        tokio::spawn(async move {
            loop {
                if let Err(e) = eventloop.poll().await {
                    tracing::error!("MQTT connection error: {:?}", e);
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            }
        });

        let topic = format!("devices/{}/messages/events/", device_id);

        Ok(Self {
            client,
            topic,
            inflight: std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_MQTT_INFLIGHT)),
        })
    }
}

#[cfg(feature = "mqtt")]
impl Sink for MqttSink {
    fn emit(&self, json: Vec<u8>) {
        let permit = match self.inflight.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!("mqtt sink: at capacity, dropping event");
                return;
            }
        };

        let topic = self.topic.clone();
        let client = self.client.clone();

        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = client.publish(topic, rumqttc::QoS::AtLeastOnce, false, json).await {
                tracing::error!("Failed to publish MQTT message: {:?}", e);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stdout_sink_emits_valid_json_line() {
        // StdoutSink writes to actual stdout; we verify it implements Sink
        // and doesn't panic on valid JSON input.
        let sink = StdoutSink;
        let json = br#"{"ts":"2025-01-01T00:00:00Z","kind":"test"}"#;
        sink.emit(json.to_vec()); // Should not panic
    }

    #[test]
    fn stdout_sink_handles_empty_input() {
        let sink = StdoutSink;
        sink.emit(Vec::new()); // Should not panic on empty input
    }

    #[test]
    fn stdout_sink_handles_binary_data() {
        let sink = StdoutSink;
        sink.emit(vec![0xFF, 0xFE, 0x00, 0x01]); // Should not panic on non-UTF8
    }

    /// Verify the Sink trait is object-safe (dyn-compatible).
    #[test]
    fn sink_trait_is_dyn_compatible() {
        let sink: Box<dyn Sink> = Box::new(StdoutSink);
        let json = br#"{"test": true}"#;
        sink.emit(json.to_vec());
    }

    #[cfg(feature = "http")]
    mod http_tests {
        use super::super::*;

        #[test]
        fn http_sink_constructs_without_auth() {
            let sink = HttpSink::new(
                "https://example.com/ingest".into(),
                None,
                None,
            );
            assert_eq!(sink.url, "https://example.com/ingest");
            assert!(sink.auth_header.is_none());
            assert!(sink.buffer_path.is_none());
        }

        #[test]
        fn http_sink_constructs_with_auth_and_buffer() {
            let sink = HttpSink::new(
                "https://example.com/v1".into(),
                Some("token-123".into()),
                Some("/tmp/buf.ndjson".into()),
            );
            assert_eq!(sink.url, "https://example.com/v1");
            assert_eq!(sink.auth_header.as_deref(), Some("Bearer token-123"));
            assert_eq!(sink.buffer_path.as_deref(), Some("/tmp/buf.ndjson"));
        }

        #[test]
        fn buffer_event_appends_to_file() {
            let path = std::env::temp_dir().join("igel_test_buffer_event.ndjson");
            let path_str = path.to_str().expect("path");

            // Clean up from any prior run
            let _ = std::fs::remove_file(&path);

            buffer_event(path_str, br#"{"line":1}"#);
            buffer_event(path_str, br#"{"line":2}"#);

            let content = std::fs::read_to_string(&path).expect("read");
            let lines: Vec<&str> = content.lines().collect();
            assert_eq!(lines.len(), 2);
            assert_eq!(lines[0], r#"{"line":1}"#);
            assert_eq!(lines[1], r#"{"line":2}"#);

            std::fs::remove_file(&path).ok();
        }

        #[tokio::test]
        async fn drain_buffer_empty_file_returns_zero() {
            let path = std::env::temp_dir().join("igel_test_drain_empty.ndjson");
            tokio::fs::write(&path, b"").await.expect("write");

            let count = drain_buffer(
                "https://example.com/ingest",
                None,
                path.to_str().expect("path"),
            ).await;
            assert_eq!(count, 0);

            tokio::fs::remove_file(&path).await.ok();
        }

        #[tokio::test]
        async fn drain_buffer_nonexistent_file_returns_zero() {
            let count = drain_buffer(
                "https://example.com/ingest",
                None,
                "/tmp/igel_nonexistent_drain_837241.ndjson",
            ).await;
            assert_eq!(count, 0);
        }
    }
}
