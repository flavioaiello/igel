use std::collections::HashMap;
use std::path::Path;

use sha2::{Digest, Sha256};
use sysinfo::{Networks, System};
use tokio::fs;
use tracing::{debug, warn};

use crate::events::*;

/// Snapshot all running processes.
pub fn collect_processes(sys: &System) -> Vec<ProcessEvent> {
    sys.processes()
        .iter()
        .map(|(pid, p)| ProcessEvent {
            pid: pid.as_u32(),
            ppid: p.parent().map(|pp| pp.as_u32()),
            name: p.name().to_string_lossy().to_string(),
            cmd: p
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy().to_string())
                .collect::<Vec<_>>()
                .join(" "),
            user: p.user_id().map(|u| u.to_string()).unwrap_or_default(),
            cpu: p.cpu_usage(),
            mem_bytes: p.memory(),
        })
        .collect()
}

/// Snapshot network interface counters.
pub fn collect_network(networks: &Networks) -> Vec<NetworkEvent> {
    networks
        .iter()
        .map(|(name, data)| NetworkEvent {
            iface: name.clone(),
            tx_bytes: data.total_transmitted(),
            rx_bytes: data.total_received(),
        })
        .collect()
}

/// Check watched files for changes. Returns events only when something changed.
pub async fn check_fim(
    paths: &[String],
    known: &mut HashMap<String, String>,
) -> Vec<FimEvent> {
    let mut out = Vec::new();

    for path_str in paths {
        let path = Path::new(path_str);
        match fs::read(path).await {
            Ok(contents) => {
                let mut h = Sha256::new();
                h.update(&contents);
                let hash = format!("{:x}", h.finalize());
                let size = contents.len() as u64;

                let prev = known.get(path_str).cloned();
                let change = match &prev {
                    Some(old) if old != &hash => "modified",
                    None => "created",
                    _ => continue,
                };

                debug!(path = path_str, change, "FIM event");
                out.push(FimEvent {
                    path: path_str.clone(),
                    sha256: hash.clone(),
                    prev_sha256: prev,
                    change,
                    size,
                });
                known.insert(path_str.clone(), hash);
            }
            Err(_) => {
                if known.remove(path_str).is_some() {
                    warn!(path = path_str, "Watched file deleted");
                    out.push(FimEvent {
                        path: path_str.clone(),
                        sha256: String::new(),
                        prev_sha256: None,
                        change: "deleted",
                        size: 0,
                    });
                }
            }
        }
    }
    out
}

/// Run basic security baseline checks (CIS-style).
pub async fn check_baseline() -> Vec<BaselineEvent> {
    let out = Vec::new();

    // Shadow file permissions
    #[cfg(target_os = "linux")]
    if let Ok(m) = fs::metadata("/etc/shadow").await {
        use std::os::unix::fs::PermissionsExt;
        let mode = m.permissions().mode();
        out.push(BaselineEvent {
            check: "shadow-perms".into(),
            category: "auth".into(),
            pass: mode & 0o077 == 0,
            detail: format!("{:o}", mode),
            severity: "high",
        });
    }

    // SSH root login
    #[cfg(target_os = "linux")]
    if let Ok(cfg) = fs::read_to_string("/etc/ssh/sshd_config").await {
        let disabled = cfg
            .lines()
            .any(|l| l.trim().eq_ignore_ascii_case("PermitRootLogin no"));
        out.push(BaselineEvent {
            check: "ssh-no-root".into(),
            category: "auth".into(),
            pass: disabled,
            detail: "PermitRootLogin".into(),
            severity: "critical",
        });
    }

    out
}

/// Heartbeat with system vitals.
pub fn heartbeat(sys: &System, events_sent: u64) -> Heartbeat {
    Heartbeat {
        os: System::name().unwrap_or_else(|| "unknown".into()),
        os_version: System::os_version().unwrap_or_else(|| "unknown".into()),
        uptime_secs: System::uptime(),
        cpu: sys.global_cpu_usage(),
        mem_pct: (sys.used_memory() as f32 / sys.total_memory().max(1) as f32) * 100.0,
        events_sent,
    }
}
