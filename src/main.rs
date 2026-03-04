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
fn emit<T: serde::Serialize>(sink: &dyn Sink, env: &Envelope<T>) {
    match serde_json::to_vec(env) {
        Ok(json) => sink.emit(&json),
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
    self_protect::secure_igel_process();

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

    // ── Sink ─────────────────────────────────────────────────
    #[cfg(feature = "mqtt")]
    let sink_instance: Box<dyn Sink> = if let Some(ref host) = cfg.mqtt_host {
        tracing::info!(host = %host, "using MQTT sink");
        Box::new(sink::MqttSink::new(
            host.clone(),
            cfg.device_id.clone(),
            cfg.mqtt_sas_token.clone(),
        ))
    } else {
        Box::new(StdoutSink)
    };

    #[cfg(feature = "http")]
    let sink_instance: Box<dyn Sink> = if let Some(ref url) = cfg.http_url {
        tracing::info!(url = %url, "using HTTP sink");
        Box::new(HttpSink::new(
            url.clone(),
            cfg.http_auth_token.clone(),
            cfg.buffer_path.clone(),
        ))
    } else {
        Box::new(StdoutSink)
    };

    #[cfg(not(any(feature = "http", feature = "mqtt")))]
    let sink_instance: Box<dyn Sink> = Box::new(StdoutSink);

    let mut events_sent: u64 = 0;

    loop {
        tokio::select! {
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
                let ev = collect::collect_connections();
                let env = Envelope::new(&cfg.device_id, "connections", ev);
                emit(&*sink_instance, &env);
                events_sent += 1;
            }
            _ = tick_listen.tick() => {
                let ev = collect::collect_listeners();
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
                for ev in tamper::check_tampering(&sys) {
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
}
