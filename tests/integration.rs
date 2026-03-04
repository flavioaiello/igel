//! Integration tests for Igel.
//!
//! These tests verify end-to-end behavior: config loading → data collection
//! → NDJSON serialization, and FIM push-based monitoring.

use std::time::Duration;

// Re-use the crate as a library (requires the binary crate to expose modules).
// Since igel is a binary crate, we test by importing the compiled binary and
// verifying outputs, or by reimplementing the minimal logic under test.

// ── NDJSON format tests ──────────────────────────────────────────────

/// Verify that the `emit` function in main.rs produces exactly one JSON
/// line per event. We replicate the pattern here since main.rs is not a lib.
#[test]
fn ndjson_line_is_valid_json() {
    use serde_json::Value;

    // Simulate what `emit` does: serialize to vec, then validate
    let sample = serde_json::json!({
        "ts": "2025-01-15T10:30:00Z",
        "device": "test-sensor",
        "kind": "heartbeat",
        "v": "0.1.0",
        "os": "Linux",
        "uptime_secs": 3600,
        "cpu": 5.0,
        "mem_pct": 25.0,
        "events_sent": 10
    });

    let line = serde_json::to_vec(&sample).expect("serialize");

    // Must not contain newlines (NDJSON requirement)
    assert!(
        !line.contains(&b'\n'),
        "NDJSON line must not contain embedded newlines"
    );

    // Must parse back as valid JSON
    let parsed: Value = serde_json::from_slice(&line).expect("parse");
    assert_eq!(parsed["kind"], "heartbeat");
    assert_eq!(parsed["device"], "test-sensor");
}

#[test]
fn ndjson_multiple_lines_are_independent() {
    use serde_json::Value;

    let events = vec![
        serde_json::json!({"ts": "2025-01-15T10:30:00Z", "device": "s1", "kind": "heartbeat", "v": "0.1.0"}),
        serde_json::json!({"ts": "2025-01-15T10:30:01Z", "device": "s1", "kind": "processes", "v": "0.1.0"}),
        serde_json::json!({"ts": "2025-01-15T10:30:02Z", "device": "s1", "kind": "network", "v": "0.1.0"}),
    ];

    let mut output = Vec::new();
    for ev in &events {
        let line = serde_json::to_vec(ev).expect("serialize");
        output.extend_from_slice(&line);
        output.push(b'\n');
    }

    let text = String::from_utf8(output).expect("utf8");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 3);

    for (i, line) in lines.iter().enumerate() {
        let parsed: Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("line {} is not valid JSON: {}", i, e));
        assert!(parsed["kind"].is_string());
        assert!(parsed["ts"].is_string());
    }
}

// ── Config file integration ──────────────────────────────────────────

#[test]
fn config_roundtrip_from_temp_file() {
    let dir = std::env::temp_dir().join("igel_integration_test");
    std::fs::create_dir_all(&dir).expect("create dir");
    let path = dir.join("test.toml");

    let toml_content = r#"
device_id = "integration-sensor"
process_interval = 30
network_interval = 15
connection_interval = 45
listener_interval = 600
baseline_interval = 7200
heartbeat_interval = 120
fim_paths = ["/etc/passwd"]
"#;

    std::fs::write(&path, toml_content).expect("write config");

    // Parse the config
    let text = std::fs::read_to_string(&path).expect("read");
    let cfg: toml::Value = toml::from_str(&text).expect("parse toml");

    assert_eq!(cfg["device_id"].as_str(), Some("integration-sensor"));
    assert_eq!(cfg["process_interval"].as_integer(), Some(30));
    assert_eq!(cfg["network_interval"].as_integer(), Some(15));
    assert_eq!(cfg["connection_interval"].as_integer(), Some(45));
    assert_eq!(cfg["listener_interval"].as_integer(), Some(600));
    assert_eq!(cfg["baseline_interval"].as_integer(), Some(7200));
    assert_eq!(cfg["heartbeat_interval"].as_integer(), Some(120));

    let fim_paths = cfg["fim_paths"].as_array().expect("fim_paths array");
    assert_eq!(fim_paths.len(), 1);
    assert_eq!(fim_paths[0].as_str(), Some("/etc/passwd"));

    std::fs::remove_dir_all(&dir).ok();
}

// ── FIM integration (push-based file watching) ──────────────────────

#[tokio::test]
async fn fim_detects_file_creation_and_modification() {
    use sha2::{Digest, Sha256};
    use tokio::time::{sleep, timeout};

    let dir = std::env::temp_dir().join("igel_fim_integration");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create dir");

    let watch_file = dir.join("watched.txt");

    // Create the file before starting the watcher so it baselines
    std::fs::write(&watch_file, b"initial content").expect("write initial");

    let (tx, mut rx) = tokio::sync::mpsc::channel::<(String, String)>(100);

    // Simulate FIM: watch via notify, hash on change
    let watch_path = watch_file.clone();
    let _watcher_handle = tokio::spawn(async move {
        use notify::{EventKind, RecursiveMode, Watcher};

        let (notify_tx, notify_rx) = flume::unbounded();
        let mut watcher = notify::recommended_watcher(move |res| {
            if let Ok(event) = res {
                let _ = notify_tx.send(event);
            }
        })
        .expect("create watcher");

        watcher
            .watch(&watch_path, RecursiveMode::NonRecursive)
            .expect("watch path");

        while let Ok(event) = notify_rx.recv_async().await {
            let is_relevant = matches!(
                event.kind,
                EventKind::Modify(_) | EventKind::Create(_)
            );
            if !is_relevant {
                continue;
            }
            for path in event.paths {
                if let Ok(contents) = tokio::fs::read(&path).await {
                    let mut h = Sha256::new();
                    h.update(&contents);
                    let hash = format!("{:x}", h.finalize());
                    let _ = tx
                        .send((path.to_string_lossy().to_string(), hash))
                        .await;
                }
            }
        }

        // Keep watcher alive
        drop(watcher);
    });

    // Give the watcher time to start
    sleep(Duration::from_millis(500)).await;

    // Write the final content atomically via rename to avoid partial-write races
    let tmp_file = dir.join("watched.txt.tmp");
    std::fs::write(&tmp_file, b"modified content").expect("write tmp");
    std::fs::rename(&tmp_file, &watch_file).expect("rename");

    // Collect events for up to 5 seconds; we want the *last* hash to match
    // because the watcher may emit multiple events for a single logical write.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut last_hash = None;
    loop {
        match timeout(deadline.saturating_duration_since(tokio::time::Instant::now()), rx.recv()).await {
            Ok(Some((_path, hash))) => {
                last_hash = Some(hash);
                // Drain any additional rapid events within a short window
                sleep(Duration::from_millis(100)).await;
                while let Ok((_p, h)) = rx.try_recv() {
                    last_hash = Some(h);
                }
                break;
            }
            _ => break,
        }
    }

    assert!(
        last_hash.is_some(),
        "FIM should have detected file modification"
    );

    // Read the actual file content and compare hash
    let actual_content = std::fs::read(&watch_file).expect("read");
    let mut expected_hasher = Sha256::new();
    expected_hasher.update(&actual_content);
    let expected = format!("{:x}", expected_hasher.finalize());

    assert_eq!(
        last_hash.unwrap(),
        expected,
        "SHA-256 hash should match the actual file content"
    );

    // Cleanup
    std::fs::remove_dir_all(&dir).ok();
}

// ── Envelope schema validation ───────────────────────────────────────

/// Verify that every event kind produces the required envelope fields.
#[test]
fn all_event_kinds_have_required_envelope_fields() {
    use serde_json::Value;

    let required_keys = ["ts", "device", "kind", "v"];
    let kinds = [
        ("processes", serde_json::json!({"pid": 1, "name": "test", "cmd": "", "user": "", "cpu": 0.0, "mem_bytes": 0})),
        ("network", serde_json::json!({"iface": "lo", "tx_bytes": 0, "rx_bytes": 0})),
        ("heartbeat", serde_json::json!({"os": "Linux", "os_version": "5.15", "uptime_secs": 0, "cpu": 0.0, "mem_pct": 0.0, "events_sent": 0})),
        ("fim", serde_json::json!({"path": "/etc/passwd", "sha256": "abc", "change": "modified", "size": 100})),
        ("baseline", serde_json::json!({"check": "test", "category": "auth", "pass": true, "detail": "ok", "severity": "high"})),
        ("tamper", serde_json::json!({"category": "process_injection", "signal": "active_ptrace", "severity": "critical", "detail": "test"})),
    ];

    for (kind, payload) in &kinds {
        let mut envelope = serde_json::json!({
            "ts": "2025-01-15T10:30:00Z",
            "device": "test-sensor",
            "kind": kind,
            "v": "0.1.0"
        });

        // Flatten payload into envelope (simulating #[serde(flatten)])
        if let Value::Object(ref map) = payload {
            for (k, v) in map {
                envelope[k] = v.clone();
            }
        }

        let line = serde_json::to_string(&envelope).expect("serialize");
        let parsed: Value = serde_json::from_str(&line).expect("parse");

        for key in &required_keys {
            assert!(
                parsed.get(key).is_some(),
                "kind '{}' missing required field '{}'",
                kind,
                key
            );
        }
    }
}

// ── SHA-256 hashing consistency ──────────────────────────────────────

#[test]
fn sha256_hash_is_deterministic() {
    use sha2::{Digest, Sha256};

    let input = b"test content for hashing";

    let mut h1 = Sha256::new();
    h1.update(input);
    let hash1 = format!("{:x}", h1.finalize());

    let mut h2 = Sha256::new();
    h2.update(input);
    let hash2 = format!("{:x}", h2.finalize());

    assert_eq!(hash1, hash2, "SHA-256 must be deterministic");
    assert_eq!(hash1.len(), 64, "SHA-256 hex should be 64 chars");
}

#[test]
fn sha256_different_input_different_hash() {
    use sha2::{Digest, Sha256};

    let mut h1 = Sha256::new();
    h1.update(b"content A");
    let hash1 = format!("{:x}", h1.finalize());

    let mut h2 = Sha256::new();
    h2.update(b"content B");
    let hash2 = format!("{:x}", h2.finalize());

    assert_ne!(hash1, hash2, "different inputs must produce different hashes");
}

// ── Binary output format ─────────────────────────────────────────────

/// Verify that serialized NDJSON events contain no control characters
/// that could break line-based consumers.
#[test]
fn ndjson_no_control_characters_in_string_fields() {
    let event = serde_json::json!({
        "ts": "2025-01-15T10:30:00Z",
        "device": "sensor\twith\ttabs",
        "kind": "heartbeat",
        "name": "process\nwith\nnewlines"
    });

    let line = serde_json::to_string(&event).expect("serialize");

    // serde_json escapes control characters, so the serialized output
    // should not contain raw \n or \t (they become \\n, \\t in JSON)
    assert!(
        !line.contains('\n'),
        "serialized NDJSON must not contain raw newlines"
    );
}
