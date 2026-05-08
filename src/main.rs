use std::env;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;
use sysinfo::{Networks, System};
use tokio::time::{interval, timeout};

mod collect;
mod config;
mod events;
mod self_protect;
mod sink;
mod tamper;

use events::Envelope;
#[cfg(feature = "http")]
use sink::HttpSink;
use sink::{Sink, StdoutSink};

/// Serialize an envelope and emit it through the sink.
/// Passes ownership of the serialized bytes to avoid a redundant copy.
fn emit<T: serde::Serialize>(sink: &dyn Sink, env: &Envelope<T>) {
    match serde_json::to_vec(env) {
        Ok(json) => sink.emit(json),
        Err(e) => tracing::error!("serialization error: {}", e),
    }
}

/// Parse RUST_LOG into a tracing level (no regex dependency).
fn parse_log_level() -> tracing::Level {
    match std::env::var("RUST_LOG")
        .as_deref()
        .map(|s| s.to_ascii_lowercase())
        .as_deref()
    {
        Ok("trace") => tracing::Level::TRACE,
        Ok("debug") => tracing::Level::DEBUG,
        Ok("warn") | Ok("warning") => tracing::Level::WARN,
        Ok("error") => tracing::Level::ERROR,
        _ => tracing::Level::INFO,
    }
}

const BLOCKING_SCAN_TIMEOUT: Duration = Duration::from_secs(15);

async fn run_bounded_blocking<T, F>(
    in_progress: Arc<AtomicBool>,
    timeout_dur: Duration,
    task_label: &'static str,
    task: F,
) -> Option<T>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    if in_progress
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        tracing::warn!(
            task = task_label,
            "previous blocking task still running; skipping tick"
        );
        return None;
    }

    struct ResetFlag(Arc<AtomicBool>);
    impl Drop for ResetFlag {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Release);
        }
    }

    let guard_flag = Arc::clone(&in_progress);
    let join = tokio::task::spawn_blocking(move || {
        let _guard = ResetFlag(guard_flag);
        task()
    });

    match timeout(timeout_dur, join).await {
        Ok(Ok(result)) => Some(result),
        Ok(Err(e)) => {
            tracing::error!(task = task_label, err = %e, "blocking task failed");
            None
        }
        Err(_) => {
            tracing::error!(
                task = task_label,
                timeout_secs = timeout_dur.as_secs(),
                "blocking task timed out"
            );
            None
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(parse_log_level())
        .init();

    // ── Self-Protection ──────────────────────────────────────────────────────
    self_protect::harden_process();

    let config_path = env::args()
        .nth(1)
        .unwrap_or_else(|| "igel.toml".to_string());
    let cfg = config::Config::load(&config_path)?;
    #[cfg(not(feature = "http"))]
    if cfg.http_url.is_some() {
        anyhow::bail!("http_url configured but binary was built without the http feature");
    }
    #[cfg(not(feature = "mqtt"))]
    if cfg.mqtt_host.is_some() {
        anyhow::bail!("mqtt_host configured but binary was built without the mqtt feature");
    }
    tracing::info!(device_id = %cfg.device_id, "igel started");

    let mut sys = System::new_all();
    let mut networks = Networks::new_with_refreshed_list();

    let mut tick_proc = interval(Duration::from_secs(cfg.process_interval));
    let mut tick_net = interval(Duration::from_secs(cfg.network_interval));
    let mut tick_conn = interval(Duration::from_secs(cfg.connection_interval));
    let mut tick_listen = interval(Duration::from_secs(cfg.listener_interval));
    let mut tick_base = interval(Duration::from_secs(cfg.baseline_interval));
    let mut tick_kernel = interval(Duration::from_secs(cfg.kernel_interval));
    let mut tick_hb = interval(Duration::from_secs(cfg.heartbeat_interval));
    let mut fim_rx = collect::start_fim_monitor(cfg.fim_paths.clone());
    let conn_scan_in_progress = Arc::new(AtomicBool::new(false));
    let listener_scan_in_progress = Arc::new(AtomicBool::new(false));
    let tamper_scan_in_progress = Arc::new(AtomicBool::new(false));

    // ── Sink (MQTT takes priority over HTTP; both fall back to stdout) ──
    let sink_instance: Box<dyn Sink> = {
        #[allow(unused_mut)]
        let mut sink: Option<Box<dyn Sink>> = None;

        #[cfg(feature = "mqtt")]
        if sink.is_none() {
            if let Some(ref host) = cfg.mqtt_host {
                match sink::MqttSink::new(
                    host.to_string(),
                    cfg.device_id.clone(),
                    cfg.mqtt_sas_token.clone(),
                ) {
                    Ok(s) => {
                        tracing::info!(host = %host, "using MQTT sink");
                        sink = Some(Box::new(s));
                    }
                    Err(e) => {
                        anyhow::bail!("MQTT sink init failed: {e}");
                    }
                }
            }
        }

        #[cfg(feature = "http")]
        if sink.is_none() {
            if let Some(ref url) = cfg.http_url {
                tracing::info!(url = %url, "using HTTP sink");
                let http_sink = HttpSink::new(
                    url.to_string(),
                    cfg.http_auth_token.clone(),
                    cfg.buffer_path.clone(),
                )?;
                sink = Some(Box::new(http_sink));
            }
        }

        sink.unwrap_or_else(|| Box::new(StdoutSink))
    };

    // ── Filesystem Sandbox (Landlock) ────────────────────────────────────────
    {
        let mut write_dirs: Vec<String> = Vec::with_capacity(1);
        if let Some(ref bp) = cfg.buffer_path {
            if let Some(parent) = std::path::Path::new(bp).parent() {
                let p = parent.to_string_lossy().to_string();
                if !p.is_empty() {
                    write_dirs.push(p);
                }
            }
        }
        self_protect::sandbox_filesystem(&cfg.fim_paths, &write_dirs);
    }

    #[cfg(target_os = "linux")]
    if cfg.enforce_kernel_lockdown {
        tracing::info!("enforcing kernel lockdown mechanisms");
        let _ = std::fs::write("/proc/sys/kernel/modules_disabled", b"1");
        let _ = std::fs::write("/proc/sys/kernel/kexec_load_disabled", b"1");
        let _ = std::fs::write("/proc/sys/kernel/unprivileged_bpf_disabled", b"1");
    }

    // ── Hardware Watchdog ────────────────────────────────────────────────────
    let mut watchdog_file = None;
    if let Some(ref path) = cfg.watchdog_path {
        match std::fs::OpenOptions::new().write(true).open(path) {
            Ok(file) => {
                tracing::info!(path = %path, "hardware watchdog initialized");
                watchdog_file = Some(file);
            }
            Err(e) => {
                tracing::warn!(path = %path, err = %e, "failed to open hardware watchdog");
            }
        }
    }

    let mut events_sent: u64 = 0;

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    // State delta trackers
    let mut known_connections = std::collections::HashSet::new();
    let mut known_listeners = std::collections::HashSet::new();
    let mut last_kernel_state: Option<String> = None;

    let state_file_path = cfg
        .buffer_path
        .as_ref()
        .map(|bp| format!("{bp}.state"))
        .unwrap_or_else(|| "/tmp/igel.state".into());
    if let Ok(state_data) = std::fs::read_to_string(&state_file_path) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&state_data) {
            if let Some(arr) = json.get("connections").and_then(|v| v.as_array()) {
                known_connections = arr
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect();
            }
            if let Some(arr) = json.get("listeners").and_then(|v| v.as_array()) {
                known_listeners = arr
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect();
            }
        }
    }

    loop {
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                if let Err(e) = result {
                    tracing::error!("signal handler error: {e}");
                }
                tracing::info!("shutting down");
                break;
            }
            _ = sigterm.recv() => {
                tracing::info!("shutting down");
                break;
            }
            _ = tick_proc.tick() => {
                sys.refresh_all();
                let ev = collect::collect_processes(&sys);
                let env = Envelope::new(&cfg.device_id, "processes", ev);
                emit(&*sink_instance, &env);
                events_sent += 1;
            }
            _ = tick_net.tick() => {
                networks.refresh(true);
                let ev = collect::collect_network(&networks);
                let env = Envelope::new(&cfg.device_id, "network", ev);
                emit(&*sink_instance, &env);
                events_sent += 1;
            }
            _ = tick_conn.tick() => {
                if let Some(evs) = run_bounded_blocking(
                    Arc::clone(&conn_scan_in_progress),
                    BLOCKING_SCAN_TIMEOUT,
                    "collect_connections",
                    collect::collect_connections,
                ).await {
                    let mut current = std::collections::HashSet::new();
                    for ev in evs {
                        let sig = format!("{}:{}->{}:{}", ev.protocol, ev.local_addr, ev.remote_addr, ev.remote_port);
                        if !known_connections.contains(&sig) {
                            let env = Envelope::new(&cfg.device_id, "connections", ev);
                            emit(&*sink_instance, &env);
                            events_sent += 1;
                        }
                        current.insert(sig);
                    }
                    known_connections = current;
                }
            }
            _ = tick_listen.tick() => {
                if let Some(evs) = run_bounded_blocking(
                    Arc::clone(&listener_scan_in_progress),
                    BLOCKING_SCAN_TIMEOUT,
                    "collect_listeners",
                    collect::collect_listeners,
                ).await {
                    let mut current = std::collections::HashSet::new();
                    for ev in evs {
                        let sig = format!("{}:{}:{}", ev.protocol, ev.addr, ev.port);
                        if !known_listeners.contains(&sig) {
                            let env = Envelope::new(&cfg.device_id, "listeners", ev);
                            emit(&*sink_instance, &env);
                            events_sent += 1;
                        }
                        current.insert(sig);
                    }
                    known_listeners = current;

                    let state_json = serde_json::json!({
                        "connections": known_connections,
                        "listeners": known_listeners,
                    });
                    let _ = std::fs::write(&state_file_path, state_json.to_string());
                }
            }
            Some(ev) = fim_rx.recv() => {
                let env = Envelope::new(&cfg.device_id, "fim", ev);
                emit(&*sink_instance, &env);
                events_sent += 1;
            }
            _ = tick_base.tick() => {
                for ev in collect::check_baseline().await {
                    if !ev.pass {
                        let env = Envelope::new(&cfg.device_id, "baseline", ev);
                        emit(&*sink_instance, &env);
                        events_sent += 1;
                    }
                }
                let mut pids = Vec::with_capacity(sys.processes().len().min(tamper::MAX_PIDS_CHECKED));
                for pid in sys.processes().keys().take(tamper::MAX_PIDS_CHECKED) {
                    pids.push(pid.as_u32());
                }
                if let Some(tamper_evs) = run_bounded_blocking(
                    Arc::clone(&tamper_scan_in_progress),
                    BLOCKING_SCAN_TIMEOUT,
                    "check_tampering",
                    move || tamper::check_tampering(&pids),
                ).await {
                    for ev in tamper_evs {
                        let env = Envelope::new(&cfg.device_id, "tamper", ev);
                        emit(&*sink_instance, &env);
                        events_sent += 1;
                    }
                }
            }
            _ = tick_kernel.tick() => {
                if let Some(ev) = collect::collect_kernel().await {
                    let is_degraded = !ev.secure_boot
                        || ev.tainted != 0
                        || !ev.modules_disabled
                        || !ev.kexec_disabled
                        || !ev.unprivileged_bpf_disabled;

                    let sig = format!("{:?}_{}", ev.module_count, ev.lockdown);

                    if is_degraded || last_kernel_state.as_deref() != Some(&sig) {
                        let env = Envelope::new(&cfg.device_id, "kernel_integrity", ev);
                        emit(&*sink_instance, &env);
                        events_sent += 1;
                        last_kernel_state = Some(sig);
                    }
                }
            }
            _ = tick_hb.tick() => {
                sys.refresh_all();
                let ev = collect::heartbeat(&sys, events_sent);
                let env = Envelope::new(&cfg.device_id, "heartbeat", ev);
                emit(&*sink_instance, &env);

                // Pet the hardware watchdog if configured
                if let Some(ref mut file) = watchdog_file {
                    use std::io::Write;
                    if let Err(e) = file.write_all(b"1") {
                        tracing::warn!(err = %e, "failed to pet hardware watchdog");
                    }
                }
            }
        }
    }

    // Attempt to gracefully close watchdog without triggering reboot
    if let Some(mut file) = watchdog_file {
        use std::io::Write;
        let _ = file.write_all(b"V");
    }

    Ok(())
}
