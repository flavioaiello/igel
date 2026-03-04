mod collect;
mod config;
mod events;
mod sink;

use std::collections::HashMap;
use std::env;

use sysinfo::{Networks, System};
use tokio::time::{interval, Duration};
use tracing::{info, error};

use config::Config;
use events::Envelope;
use sink::{Sink, StdoutSink};

fn send<T: serde::Serialize>(sink: &dyn Sink, env: &Envelope<T>) {
    match serde_json::to_vec(env) {
        Ok(json) => sink.emit(&json),
        Err(e) => tracing::error!(err = %e, "serialize"),
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .compact()
        .init();

    // ── Config ───────────────────────────────────────────────
    let config_path = env::args()
        .nth(1)
        .unwrap_or_else(|| "/etc/igel/igel.toml".into());

    let cfg = match Config::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            error!(path = config_path, err = %e, "config load failed");
            std::process::exit(1);
        }
    };

    info!(device = cfg.device_id, "igel starting");

    // ── Sink ─────────────────────────────────────────────────
    #[cfg(feature = "http")]
    let sink: Box<dyn Sink> = if let Some(ref url) = cfg.http_url {
        Box::new(sink::HttpSink::new(
            url.clone(),
            cfg.http_auth_token.clone(),
            cfg.buffer_path.clone(),
        ))
    } else {
        Box::new(StdoutSink)
    };
    #[cfg(not(feature = "http"))]
    let sink: Box<dyn Sink> = Box::new(StdoutSink);

    // ── State ────────────────────────────────────────────────
    let mut sys = System::new_all();
    let mut networks = Networks::new_with_refreshed_list();
    let mut fim_known: HashMap<String, String> = HashMap::new();
    let mut events_sent: u64 = 0;

    let mut tick_proc = interval(Duration::from_secs(cfg.process_interval));
    let mut tick_net = interval(Duration::from_secs(cfg.network_interval));
    let mut tick_conn = interval(Duration::from_secs(cfg.connection_interval));
    let mut tick_listen = interval(Duration::from_secs(cfg.listener_interval));
    let mut tick_fim = interval(Duration::from_secs(cfg.fim_interval));
    let mut tick_base = interval(Duration::from_secs(cfg.baseline_interval));
    let mut tick_hb = interval(Duration::from_secs(cfg.heartbeat_interval));
    let mut tick_drain = interval(Duration::from_secs(30));

    loop {
        tokio::select! {
            _ = tick_proc.tick() => {
                sys.refresh_all();
                for ev in collect::collect_processes(&sys) {
                    let env = Envelope::new(&cfg.device_id, "process", ev);
                    send(&*sink, &env);
                    events_sent += 1;
                }
            }
            _ = tick_net.tick() => {
                networks.refresh(true);
                for ev in collect::collect_network(&networks) {
                    let env = Envelope::new(&cfg.device_id, "network", ev);
                    send(&*sink, &env);
                    events_sent += 1;
                }
            }
            _ = tick_conn.tick() => {
                for ev in collect::collect_connections() {
                    let env = Envelope::new(&cfg.device_id, "connection", ev);
                    send(&*sink, &env);
                    events_sent += 1;
                }
            }
            _ = tick_listen.tick() => {
                for ev in collect::collect_listeners() {
                    let env = Envelope::new(&cfg.device_id, "listener", ev);
                    send(&*sink, &env);
                    events_sent += 1;
                }
            }
            _ = tick_fim.tick() => {
                for ev in collect::check_fim(&cfg.fim_paths, &mut fim_known).await {
                    let env = Envelope::new(&cfg.device_id, "fim", ev);
                    send(&*sink, &env);
                    events_sent += 1;
                }
            }
            _ = tick_base.tick() => {
                for ev in collect::check_baseline().await {
                    let env = Envelope::new(&cfg.device_id, "baseline", ev);
                    send(&*sink, &env);
                    events_sent += 1;
                }
            }
            _ = tick_hb.tick() => {
                sys.refresh_all();
                let hb = collect::heartbeat(&sys, events_sent);
                let env = Envelope::new(&cfg.device_id, "heartbeat", hb);
                send(&*sink, &env);
                events_sent += 1;
            }
            _ = tick_drain.tick() => {
                #[cfg(feature = "http")]
                if let (Some(ref url), Some(ref buf_path)) = (&cfg.http_url, &cfg.buffer_path) {
                    let drained = sink::drain_buffer(
                        url,
                        cfg.http_auth_token.as_deref(),
                        buf_path,
                    ).await;
                    if drained > 0 {
                        info!(count = drained, "drained buffered events");
                    }
                }
            }
        }
    }
}
