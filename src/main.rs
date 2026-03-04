use std::env;
use std::time::Duration;
use tokio::time::interval;
use sysinfo::{Networks, System};

mod collect;
mod config;
mod events;
mod sink;
mod tamper;
mod self_protect;

use events::Envelope;
use sink::{Sink, StdoutSink};
#[cfg(feature = "http")]
use sink::HttpSink;

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

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(parse_log_level())
        .init();

    // ── Self-Protection ──────────────────────────────────────────────────────
    self_protect::harden_process();

    let config_path = env::args().nth(1).unwrap_or_else(|| "igel.toml".to_string());
    let cfg = config::Config::load(&config_path)?;
    tracing::info!(device_id = %cfg.device_id, "igel started");

    let mut sys = System::new_all();
    let mut networks = Networks::new_with_refreshed_list();

    let mut tick_proc = interval(Duration::from_secs(cfg.process_interval));
    let mut tick_net = interval(Duration::from_secs(cfg.network_interval));
    let mut tick_conn = interval(Duration::from_secs(cfg.connection_interval));
    let mut tick_listen = interval(Duration::from_secs(cfg.listener_interval));
    let mut tick_base = interval(Duration::from_secs(cfg.baseline_interval));
    let mut tick_hb = interval(Duration::from_secs(cfg.heartbeat_interval));
    let mut fim_rx = collect::start_fim_monitor(cfg.fim_paths.clone());

    // ── Sink (MQTT takes priority over HTTP; both fall back to stdout) ──
    let sink_instance: Box<dyn Sink> = {
        #[allow(unused_mut)]
        let mut sink: Option<Box<dyn Sink>> = None;

        #[cfg(feature = "mqtt")]
        if sink.is_none() {
            if let Some(ref host) = cfg.mqtt_host {
                match sink::MqttSink::new(
                    host.clone(),
                    cfg.device_id.clone(),
                    cfg.mqtt_sas_token.clone(),
                ) {
                    Ok(s) => {
                        tracing::info!(host = %host, "using MQTT sink");
                        sink = Some(Box::new(s));
                    }
                    Err(e) => {
                        tracing::error!("MQTT sink init failed, falling back: {e}");
                    }
                }
            }
        }

        #[cfg(feature = "http")]
        if sink.is_none() {
            if let Some(ref url) = cfg.http_url {
                tracing::info!(url = %url, "using HTTP sink");
                sink = Some(Box::new(HttpSink::new(
                    url.clone(),
                    cfg.http_auth_token.clone(),
                    cfg.buffer_path.clone(),
                )));
            }
        }

        sink.unwrap_or_else(|| Box::new(StdoutSink))
    };

    // ── Filesystem Sandbox (Landlock) ────────────────────────────────────────
    {
        let mut write_dirs: Vec<String> = Vec::new();
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

    let mut events_sent: u64 = 0;

    let mut sigterm = tokio::signal::unix::signal(
        tokio::signal::unix::SignalKind::terminate(),
    )?;

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
                let ev = tokio::task::spawn_blocking(collect::collect_connections)
                    .await
                    .unwrap_or_else(|e| {
                        tracing::error!("connection scan failed: {e}");
                        Vec::new()
                    });
                let env = Envelope::new(&cfg.device_id, "connections", ev);
                emit(&*sink_instance, &env);
                events_sent += 1;
            }
            _ = tick_listen.tick() => {
                let ev = tokio::task::spawn_blocking(collect::collect_listeners)
                    .await
                    .unwrap_or_else(|e| {
                        tracing::error!("listener scan failed: {e}");
                        Vec::new()
                    });
                let env = Envelope::new(&cfg.device_id, "listeners", ev);
                emit(&*sink_instance, &env);
                events_sent += 1;
            }
            Some(ev) = fim_rx.recv() => {
                let env = Envelope::new(&cfg.device_id, "fim", ev);
                emit(&*sink_instance, &env);
                events_sent += 1;
            }
            _ = tick_base.tick() => {
                for ev in collect::check_baseline().await {
                    let env = Envelope::new(&cfg.device_id, "baseline", ev);
                    emit(&*sink_instance, &env);
                    events_sent += 1;
                }
                let pids: Vec<u32> = sys.processes().keys().map(|p| p.as_u32()).collect();
                let tamper_evs = tokio::task::spawn_blocking(move || {
                    tamper::check_tampering(&pids)
                }).await.unwrap_or_else(|e| {
                    tracing::error!("tamper check failed: {e}");
                    Vec::new()
                });
                for ev in tamper_evs {
                    let env = Envelope::new(&cfg.device_id, "tamper", ev);
                    emit(&*sink_instance, &env);
                    events_sent += 1;
                }
            }
            _ = tick_hb.tick() => {
                sys.refresh_all();
                let ev = collect::heartbeat(&sys, events_sent);
                let env = Envelope::new(&cfg.device_id, "heartbeat", ev);
                emit(&*sink_instance, &env);
            }
        }
    }

    Ok(())
}
