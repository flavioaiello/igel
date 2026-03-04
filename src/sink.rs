/// Abstraction over output destination.
/// Accepts a pre-serialized JSON line (bytes) to stay dyn-compatible.
pub trait Sink {
    fn emit(&self, json: &[u8]);
}

// ── Stdout (default) ─────────────────────────────────────────────

/// Writes NDJSON to stdout – zero config, pipeable to any consumer.
pub struct StdoutSink;

impl Sink for StdoutSink {
    fn emit(&self, json: &[u8]) {
        use std::io::Write;
        let stdout = std::io::stdout();
        let mut lock = stdout.lock();
        let _ = lock.write_all(json);
        let _ = lock.write_all(b"\n");
    }
}

#[cfg(feature = "http")]
use tracing::{debug, error};

#[cfg(feature = "http")]
pub struct HttpSink {
    client: reqwest::Client,
    url: String,
}

#[cfg(feature = "http")]
impl HttpSink {
    pub fn new(url: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            url,
        }
    }
}

#[cfg(feature = "http")]
impl Sink for HttpSink {
    fn emit(&self, json: &[u8]) {
        let body = json.to_vec();
        let url = self.url.clone();
        let client = self.client.clone();
        // Fire-and-forget; we don't block the event loop on delivery.
        tokio::spawn(async move {
            match client
                .post(&url)
                .header("content-type", "application/json")
                .body(body)
                .send()
                .await
            {
                Ok(resp) => debug!(status = resp.status().as_u16(), "http sink"),
                Err(e) => error!(err = %e, "http sink"),
            }
        });
    }
}
