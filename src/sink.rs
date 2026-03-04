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
        if lock.write_all(json).is_err() || lock.write_all(b"\n").is_err() {
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
    auth_token: Option<String>,
    buffer_path: Option<String>,
}

#[cfg(feature = "http")]
impl HttpSink {
    pub fn new(url: String, auth_token: Option<String>, buffer_path: Option<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            url,
            auth_token,
            buffer_path,
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
    fn emit(&self, json: &[u8]) {
        let body = json.to_vec();
        let url = self.url.clone();
        let client = self.client.clone();
        let auth = self.auth_token.clone();
        let buffer_path = self.buffer_path.clone();

        tokio::spawn(async move {
            let mut req = client
                .post(&url)
                .header("content-type", "application/json");

            if let Some(ref token) = auth {
                req = req.header("authorization", format!("Bearer {}", token));
            }

            match req.body(body.clone()).send().await {
                Ok(resp) if resp.status().is_success() => {
                    debug!(status = resp.status().as_u16(), "http sink");
                }
                Ok(resp) => {
                    error!(status = resp.status().as_u16(), "http sink non-2xx");
                    if let Some(ref path) = buffer_path {
                        buffer_event(path, &body);
                    }
                }
                Err(e) => {
                    error!(err = %e, "http sink");
                    if let Some(ref path) = buffer_path {
                        buffer_event(path, &body);
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
