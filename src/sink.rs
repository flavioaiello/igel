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
const HTTP_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
#[cfg(feature = "http")]
const MAX_BUFFER_EVENT_BYTES: usize = 64 * 1024;
#[cfg(feature = "http")]
const MAX_BUFFER_FILE_BYTES: u64 = 2 * 1024 * 1024;
#[cfg(feature = "http")]
const MAX_DRAIN_LINES: usize = 4096;

#[cfg(feature = "http")]
pub struct HttpSink {
    client: reqwest::Client,
    url: String,
    /// Pre-computed "Bearer <token>" header value — avoids `format!` per request.
    auth_header: Option<String>,
    buffer_path: Option<String>,
    inflight: std::sync::Arc<tokio::sync::Semaphore>,
    buffer_lock: std::sync::Arc<std::sync::Mutex<()>>,
}

#[cfg(feature = "http")]
/// Maximum concurrent inflight HTTP POST requests.
const MAX_HTTP_INFLIGHT: usize = 16;

#[cfg(feature = "http")]
impl HttpSink {
    pub fn new(
        url: String,
        auth_token: Option<String>,
        buffer_path: Option<String>,
    ) -> anyhow::Result<Self> {
        let auth_header = auth_token.map(|t| format!("Bearer {}", t));
        let client = reqwest::Client::builder()
            .timeout(HTTP_REQUEST_TIMEOUT)
            .build()?;
        Ok(Self {
            client,
            url,
            auth_header,
            buffer_path,
            inflight: std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_HTTP_INFLIGHT)),
            buffer_lock: std::sync::Arc::new(std::sync::Mutex::new(())),
        })
    }
}

#[cfg(feature = "http")]
fn open_buffer_file_for_append(path: &str) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true).read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    options.open(path)
}

#[cfg(feature = "http")]
fn sync_parent_dir(path: &std::path::Path) {
    if let Some(parent) = path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
}

/// Append a failed event to the on-disk buffer for later retry.
#[cfg(feature = "http")]
fn buffer_event(path: &str, json: &[u8]) -> bool {
    use std::io::Write;

    if json.len() > MAX_BUFFER_EVENT_BYTES {
        error!(
            size = json.len(),
            cap = MAX_BUFFER_EVENT_BYTES,
            "buffered event exceeds configured size cap"
        );
        return false;
    }

    let mut f = match open_buffer_file_for_append(path) {
        Ok(f) => f,
        Err(e) => {
            error!(path, err = %e, "buffer open failed");
            return false;
        }
    };
    let existing = match f.metadata() {
        Ok(m) => m.len(),
        Err(e) => {
            error!(path, err = %e, "buffer metadata failed");
            return false;
        }
    };
    let new_size = existing.saturating_add(json.len() as u64 + 1);
    if new_size > MAX_BUFFER_FILE_BYTES {
        error!(
            path = path,
            size = new_size,
            cap = MAX_BUFFER_FILE_BYTES,
            "buffer file size cap reached; dropping buffered event"
        );
        return false;
    }

    if let Err(e) = f.write_all(json).and_then(|_| f.write_all(b"\n")) {
        error!(path, err = %e, "buffer write failed");
        return false;
    }
    if let Err(e) = f.sync_data() {
        error!(path, err = %e, "buffer sync failed");
        return false;
    }
    sync_parent_dir(std::path::Path::new(path));
    true
}

#[cfg(feature = "http")]
fn queue_buffer_event(
    path: String,
    json: Vec<u8>,
    buffer_lock: std::sync::Arc<std::sync::Mutex<()>>,
) {
    tokio::spawn(async move {
        let _ = tokio::task::spawn_blocking(move || {
            let _guard = match buffer_lock.lock() {
                Ok(guard) => guard,
                Err(e) => {
                    error!(err = %e, "buffer lock poisoned");
                    return false;
                }
            };
            buffer_event(&path, &json)
        })
        .await;
    });
}

#[cfg(feature = "http")]
fn partition_buffer_content(content: &str) -> (Vec<&str>, String) {
    let mut deliver = Vec::with_capacity(MAX_DRAIN_LINES.min(128));
    let mut remaining = String::new();
    for line in content.lines().filter(|line| !line.is_empty()) {
        if deliver.len() < MAX_DRAIN_LINES {
            deliver.push(line);
        } else {
            if !remaining.is_empty() {
                remaining.push('\n');
            }
            remaining.push_str(line);
        }
    }
    if !remaining.is_empty() {
        remaining.push('\n');
    }
    (deliver, remaining)
}

#[cfg(feature = "http")]
fn buffer_temp_path(path: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut file_name = path.file_name()?.to_os_string();
    file_name.push(".tmp");
    Some(path.with_file_name(file_name))
}

#[cfg(feature = "http")]
fn rewrite_buffer_durable_blocking(path: &str, remaining: &str) -> bool {
    use std::io::Write;

    let path = std::path::Path::new(path);
    if std::fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
    {
        error!(path = %path.display(), "refusing to rewrite symlink buffer path");
        return false;
    }
    let tmp_path = match buffer_temp_path(path) {
        Some(path) => path,
        None => {
            error!(path = %path.display(), "invalid buffer path");
            return false;
        }
    };
    let _ = std::fs::remove_file(&tmp_path);

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }

    let mut tmp = match options.open(&tmp_path) {
        Ok(file) => file,
        Err(e) => {
            error!(path = %tmp_path.display(), err = %e, "failed to create buffer temp file");
            return false;
        }
    };
    if let Err(e) = tmp
        .write_all(remaining.as_bytes())
        .and_then(|_| tmp.sync_all())
    {
        error!(path = %tmp_path.display(), err = %e, "failed to write buffer temp file");
        let _ = std::fs::remove_file(&tmp_path);
        return false;
    }
    drop(tmp);

    if let Err(e) = std::fs::rename(&tmp_path, path) {
        error!(path = %path.display(), err = %e, "failed to replace buffer file");
        let _ = std::fs::remove_file(&tmp_path);
        return false;
    }
    sync_parent_dir(path);
    true
}

#[cfg(feature = "http")]
impl Sink for HttpSink {
    fn emit(&self, json: Vec<u8>) {
        let permit = match self.inflight.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!("http sink: at capacity, buffering event");
                if let Some(path) = self.buffer_path.clone() {
                    queue_buffer_event(path, json, self.buffer_lock.clone());
                }
                return;
            }
        };

        let url = self.url.clone();
        let client = self.client.clone();
        let auth_header = self.auth_header.clone();
        let buffer_path = self.buffer_path.clone();
        let buffer_lock = self.buffer_lock.clone();

        tokio::spawn(async move {
            let _permit = permit;
            let mut req = client.post(&url).header("content-type", "application/json");

            if let Some(ref header_val) = auth_header {
                req = req.header("authorization", header_val.as_str());
            }

            match req.body(json.clone()).send().await {
                Ok(resp) if resp.status().is_success() => {
                    debug!(status = resp.status().as_u16(), "http sink");
                }
                Ok(resp) => {
                    error!(status = resp.status().as_u16(), "http sink non-2xx");
                    if let Some(path) = buffer_path {
                        queue_buffer_event(path, json, buffer_lock);
                    }
                }
                Err(e) => {
                    error!(err = %e, "http sink");
                    if let Some(path) = buffer_path {
                        queue_buffer_event(path, json, buffer_lock);
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
#[cfg_attr(not(test), allow(dead_code))]
pub async fn drain_buffer(url: &str, auth_token: Option<&str>, buffer_path: &str) -> usize {
    let size = match tokio::fs::metadata(buffer_path).await {
        Ok(meta) => meta.len(),
        Err(_) => return 0,
    };
    if size == 0 {
        return 0;
    }
    if size > MAX_BUFFER_FILE_BYTES {
        error!(
            path = buffer_path,
            size,
            cap = MAX_BUFFER_FILE_BYTES,
            "refusing to drain oversized buffer file"
        );
        return 0;
    }

    let content = match tokio::fs::read_to_string(buffer_path).await {
        Ok(c) if !c.is_empty() => c,
        _ => return 0,
    };

    let client = match reqwest::Client::builder()
        .timeout(HTTP_REQUEST_TIMEOUT)
        .build()
    {
        Ok(client) => client,
        Err(e) => {
            error!(err = %e, "failed to build client for drain");
            return 0;
        }
    };
    let (lines, remaining) = partition_buffer_content(&content);
    let total = lines.len();
    if total == 0 {
        return 0;
    }

    for line in &lines {
        if line.len() > MAX_BUFFER_EVENT_BYTES {
            error!(
                size = line.len(),
                cap = MAX_BUFFER_EVENT_BYTES,
                "refusing to drain oversized buffered line"
            );
            return 0;
        }
        let mut req = client.post(url).header("content-type", "application/json");
        if let Some(token) = auth_token {
            req = req.header("authorization", format!("Bearer {}", token));
        }
        match req.body(line.to_string()).send().await {
            Ok(resp) if resp.status().is_success() => {}
            _ => return 0, // abort drain on first failure — retry next cycle
        }
    }

    match tokio::task::spawn_blocking({
        let buffer_path = buffer_path.to_string();
        move || rewrite_buffer_durable_blocking(&buffer_path, &remaining)
    })
    .await
    {
        Ok(true) => total,
        _ => 0,
    }
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
        let mut mqttoptions = rumqttc::MqttOptions::new(&device_id, host.as_str(), 8883);
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
            if let Err(e) = client
                .publish(topic, rumqttc::QoS::AtLeastOnce, false, json)
                .await
            {
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
            let sink =
                HttpSink::new("https://example.com/ingest".into(), None, None).expect("http sink");
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
            )
            .expect("http sink");
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

        #[test]
        fn partition_buffer_content_preserves_undelivered_lines() {
            let mut content = String::new();
            for i in 0..(MAX_DRAIN_LINES + 2) {
                content.push_str(&format!(r#"{{"line":{}}}"#, i));
                content.push('\n');
            }

            let (deliver, remaining) = partition_buffer_content(&content);

            assert_eq!(deliver.len(), MAX_DRAIN_LINES);
            assert!(remaining.contains(&format!(r#"{{"line":{}}}"#, MAX_DRAIN_LINES)));
            assert!(remaining.contains(&format!(r#"{{"line":{}}}"#, MAX_DRAIN_LINES + 1)));
        }

        #[cfg(unix)]
        #[test]
        fn buffer_event_rejects_symlink_path() {
            let target = std::env::temp_dir().join("igel_test_buffer_target.ndjson");
            let link = std::env::temp_dir().join("igel_test_buffer_link.ndjson");
            std::fs::write(&target, b"").expect("write target");
            let _ = std::fs::remove_file(&link);
            std::os::unix::fs::symlink(&target, &link).expect("symlink");

            let written = buffer_event(link.to_str().expect("path"), br#"{"line":1}"#);
            let target_content = std::fs::read_to_string(&target).expect("read target");

            assert!(!written);
            assert!(target_content.is_empty());

            std::fs::remove_file(&link).ok();
            std::fs::remove_file(&target).ok();
        }

        #[tokio::test]
        async fn drain_buffer_empty_file_returns_zero() {
            let path = std::env::temp_dir().join("igel_test_drain_empty.ndjson");
            tokio::fs::write(&path, b"").await.expect("write");

            let count = drain_buffer(
                "https://example.com/ingest",
                None,
                path.to_str().expect("path"),
            )
            .await;
            assert_eq!(count, 0);

            tokio::fs::remove_file(&path).await.ok();
        }

        #[tokio::test]
        async fn drain_buffer_nonexistent_file_returns_zero() {
            let count = drain_buffer(
                "https://example.com/ingest",
                None,
                "/tmp/igel_nonexistent_drain_837241.ndjson",
            )
            .await;
            assert_eq!(count, 0);
        }
    }
}
