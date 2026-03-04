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

// ── Connection & listener collectors (Linux /proc/net) ───────

#[cfg(target_os = "linux")]
mod procnet {
    use std::collections::HashMap;

    /// Parse a hex IPv4 address from /proc/net/tcp format.
    pub fn parse_ipv4(hex: &str) -> String {
        let val = u32::from_str_radix(hex, 16).unwrap_or(0);
        format!(
            "{}.{}.{}.{}",
            val & 0xFF,
            (val >> 8) & 0xFF,
            (val >> 16) & 0xFF,
            (val >> 24) & 0xFF
        )
    }

    /// Parse a hex IPv6 address from /proc/net/tcp6 format.
    pub fn parse_ipv6(hex: &str) -> String {
        if hex.len() != 32 {
            return hex.to_string();
        }
        let mut bytes = [0u8; 16];
        for i in 0..4 {
            let group = &hex[i * 8..(i + 1) * 8];
            let val = u32::from_str_radix(group, 16).unwrap_or(0);
            // /proc stores each 32-bit group in host (little-endian) order
            bytes[i * 4] = (val & 0xFF) as u8;
            bytes[i * 4 + 1] = ((val >> 8) & 0xFF) as u8;
            bytes[i * 4 + 2] = ((val >> 16) & 0xFF) as u8;
            bytes[i * 4 + 3] = ((val >> 24) & 0xFF) as u8;
        }
        std::net::Ipv6Addr::from(bytes).to_string()
    }

    pub fn parse_port(hex: &str) -> u16 {
        u16::from_str_radix(hex, 16).unwrap_or(0)
    }

    pub fn tcp_state(hex: &str) -> &'static str {
        match u8::from_str_radix(hex, 16).unwrap_or(0) {
            0x01 => "ESTABLISHED",
            0x02 => "SYN_SENT",
            0x03 => "SYN_RECV",
            0x04 => "FIN_WAIT1",
            0x05 => "FIN_WAIT2",
            0x06 => "TIME_WAIT",
            0x07 => "CLOSE",
            0x08 => "CLOSE_WAIT",
            0x09 => "LAST_ACK",
            0x0A => "LISTEN",
            0x0B => "CLOSING",
            _ => "UNKNOWN",
        }
    }

    pub struct RawConnection {
        pub local_addr: String,
        pub local_port: u16,
        pub remote_addr: String,
        pub remote_port: u16,
        pub state: &'static str,
        pub inode: u64,
    }

    /// Build inode → (pid, process_name) map from /proc/[pid]/fd/.
    pub fn build_inode_map() -> HashMap<u64, (u32, String)> {
        use std::fs;
        let mut map = HashMap::new();
        let proc_dir = match fs::read_dir("/proc") {
            Ok(d) => d,
            Err(_) => return map,
        };
        for entry in proc_dir.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            let pid: u32 = match name_str.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };
            let comm = fs::read_to_string(format!("/proc/{}/comm", pid))
                .unwrap_or_default()
                .trim()
                .to_string();
            let fd_dir = format!("/proc/{}/fd", pid);
            let entries = match fs::read_dir(&fd_dir) {
                Ok(d) => d,
                Err(_) => continue,
            };
            for fd_entry in entries.flatten() {
                if let Ok(link) = fs::read_link(fd_entry.path()) {
                    let link_str = link.to_string_lossy().to_string();
                    if let Some(inode_str) = link_str
                        .strip_prefix("socket:[")
                        .and_then(|s| s.strip_suffix(']'))
                    {
                        if let Ok(inode) = inode_str.parse::<u64>() {
                            map.insert(inode, (pid, comm.clone()));
                        }
                    }
                }
            }
        }
        map
    }

    /// Parse a /proc/net/{tcp,tcp6,udp,udp6} file.
    pub fn parse_proc_net(path: &str, is_ipv6: bool) -> Vec<RawConnection> {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };
        let mut conns = Vec::new();
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 {
                continue;
            }
            let (local_addr_hex, local_port_hex) = match fields[1].rsplit_once(':') {
                Some(pair) => pair,
                None => continue,
            };
            let (remote_addr_hex, remote_port_hex) = match fields[2].rsplit_once(':') {
                Some(pair) => pair,
                None => continue,
            };
            let local_addr = if is_ipv6 {
                parse_ipv6(local_addr_hex)
            } else {
                parse_ipv4(local_addr_hex)
            };
            let remote_addr = if is_ipv6 {
                parse_ipv6(remote_addr_hex)
            } else {
                parse_ipv4(remote_addr_hex)
            };
            conns.push(RawConnection {
                local_addr,
                local_port: parse_port(local_port_hex),
                remote_addr,
                remote_port: parse_port(remote_port_hex),
                state: tcp_state(fields[3]),
                inode: fields[9].parse().unwrap_or(0),
            });
        }
        conns
    }
}

/// Snapshot all active TCP/UDP connections with PID resolution (Linux).
#[cfg(target_os = "linux")]
pub fn collect_connections() -> Vec<ConnectionEvent> {
    let inode_map = procnet::build_inode_map();
    let mut events = Vec::new();
    let sources = [
        ("/proc/net/tcp", "tcp", false),
        ("/proc/net/tcp6", "tcp6", true),
        ("/proc/net/udp", "udp", false),
        ("/proc/net/udp6", "udp6", true),
    ];
    for (path, protocol, is_ipv6) in &sources {
        for conn in procnet::parse_proc_net(path, *is_ipv6) {
            let (pid, process_name) = inode_map
                .get(&conn.inode)
                .map(|(p, n)| (Some(*p), Some(n.clone())))
                .unwrap_or((None, None));
            events.push(ConnectionEvent {
                protocol: protocol.to_string(),
                local_addr: conn.local_addr,
                local_port: conn.local_port,
                remote_addr: conn.remote_addr,
                remote_port: conn.remote_port,
                state: conn.state.to_string(),
                pid,
                process_name,
            });
        }
    }
    events
}

#[cfg(not(target_os = "linux"))]
pub fn collect_connections() -> Vec<ConnectionEvent> {
    Vec::new()
}

/// Snapshot all listening network sockets with PID resolution (Linux).
#[cfg(target_os = "linux")]
pub fn collect_listeners() -> Vec<ListenerEvent> {
    let inode_map = procnet::build_inode_map();
    let mut events = Vec::new();
    let sources = [
        ("/proc/net/tcp", "tcp", false),
        ("/proc/net/tcp6", "tcp6", true),
        ("/proc/net/udp", "udp", false),
        ("/proc/net/udp6", "udp6", true),
    ];
    for (path, protocol, is_ipv6) in &sources {
        for conn in procnet::parse_proc_net(path, *is_ipv6) {
            // TCP: LISTEN state; UDP: bound with no specific remote peer
            let is_listener = if protocol.starts_with("tcp") {
                conn.state == "LISTEN"
            } else {
                conn.remote_port == 0
            };
            if !is_listener {
                continue;
            }
            let (pid, process_name) = inode_map
                .get(&conn.inode)
                .map(|(p, n)| (Some(*p), Some(n.clone())))
                .unwrap_or((None, None));
            events.push(ListenerEvent {
                protocol: protocol.to_string(),
                addr: conn.local_addr,
                port: conn.local_port,
                pid,
                process_name,
            });
        }
    }
    events
}

#[cfg(not(target_os = "linux"))]
pub fn collect_listeners() -> Vec<ListenerEvent> {
    Vec::new()
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

/// Run security baseline checks (CIS-style, 15 checks).
pub async fn check_baseline() -> Vec<BaselineEvent> {
    #[allow(unused_mut)]
    let mut out = Vec::new();

    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::PermissionsExt;

        // ── Authentication ───────────────────────────────────

        // CIS 6.1.3 – /etc/shadow permissions
        if let Ok(m) = fs::metadata("/etc/shadow").await {
            let mode = m.permissions().mode();
            out.push(BaselineEvent {
                check: "shadow-perms".into(),
                category: "auth".into(),
                pass: mode & 0o077 == 0,
                detail: format!("{:o}", mode),
                severity: "high",
            });
        }

        // CIS 6.1.2 – /etc/passwd permissions
        if let Ok(m) = fs::metadata("/etc/passwd").await {
            let mode = m.permissions().mode();
            out.push(BaselineEvent {
                check: "passwd-perms".into(),
                category: "auth".into(),
                pass: mode & 0o022 == 0,
                detail: format!("{:o}", mode),
                severity: "high",
            });
        }

        // CIS 5.4.1.1 – Password max age
        if let Ok(content) = fs::read_to_string("/etc/login.defs").await {
            let max_days = content.lines().find_map(|l| {
                let l = l.trim();
                if !l.starts_with('#') && l.starts_with("PASS_MAX_DAYS") {
                    l.split_whitespace().nth(1)?.parse::<u32>().ok()
                } else {
                    None
                }
            });
            out.push(BaselineEvent {
                check: "password-max-age".into(),
                category: "auth".into(),
                pass: max_days.map_or(false, |d| d <= 90),
                detail: max_days.map_or("not set".into(), |d| format!("{} days", d)),
                severity: "medium",
            });
        }

        // ── SSH hardening ────────────────────────────────────

        if let Ok(sshd) = fs::read_to_string("/etc/ssh/sshd_config").await {
            // CIS 5.2.10 – SSH root login
            let no_root = sshd
                .lines()
                .any(|l| l.trim().eq_ignore_ascii_case("PermitRootLogin no"));
            out.push(BaselineEvent {
                check: "ssh-no-root".into(),
                category: "auth".into(),
                pass: no_root,
                detail: "PermitRootLogin".into(),
                severity: "critical",
            });

            // CIS 5.2.7 – SSH MaxAuthTries
            let max_auth = sshd.lines().find_map(|l| {
                let l = l.trim();
                if !l.starts_with('#') && l.starts_with("MaxAuthTries") {
                    l.split_whitespace().nth(1)?.parse::<u32>().ok()
                } else {
                    None
                }
            });
            out.push(BaselineEvent {
                check: "ssh-max-auth-tries".into(),
                category: "auth".into(),
                pass: max_auth.map_or(false, |n| n <= 4),
                detail: max_auth.map_or("not set".into(), |n| n.to_string()),
                severity: "medium",
            });

            // CIS 5.2.11 – SSH PermitEmptyPasswords
            let no_empty = sshd
                .lines()
                .any(|l| l.trim().eq_ignore_ascii_case("PermitEmptyPasswords no"));
            out.push(BaselineEvent {
                check: "ssh-no-empty-passwords".into(),
                category: "auth".into(),
                pass: no_empty,
                detail: "PermitEmptyPasswords".into(),
                severity: "high",
            });
        }

        // ── Network kernel parameters ────────────────────────

        // CIS 3.1.1 – IP forwarding
        if let Ok(val) = fs::read_to_string("/proc/sys/net/ipv4/ip_forward").await {
            out.push(BaselineEvent {
                check: "ip-forwarding-disabled".into(),
                category: "network".into(),
                pass: val.trim() == "0",
                detail: val.trim().to_string(),
                severity: "medium",
            });
        }

        // CIS 3.2.8 – TCP SYN cookies
        if let Ok(val) = fs::read_to_string("/proc/sys/net/ipv4/tcp_syncookies").await {
            out.push(BaselineEvent {
                check: "syn-cookies-enabled".into(),
                category: "network".into(),
                pass: val.trim() == "1",
                detail: val.trim().to_string(),
                severity: "medium",
            });
        }

        // CIS 3.2.2 – ICMP redirects
        if let Ok(val) =
            fs::read_to_string("/proc/sys/net/ipv4/conf/all/accept_redirects").await
        {
            out.push(BaselineEvent {
                check: "icmp-redirects-disabled".into(),
                category: "network".into(),
                pass: val.trim() == "0",
                detail: val.trim().to_string(),
                severity: "medium",
            });
        }

        // CIS 3.2.1 – Source routing
        if let Ok(val) =
            fs::read_to_string("/proc/sys/net/ipv4/conf/all/accept_source_route").await
        {
            out.push(BaselineEvent {
                check: "source-route-disabled".into(),
                category: "network".into(),
                pass: val.trim() == "0",
                detail: val.trim().to_string(),
                severity: "medium",
            });
        }

        // ── System hardening ─────────────────────────────────

        // CIS 1.5.3 – ASLR
        if let Ok(val) = fs::read_to_string("/proc/sys/kernel/randomize_va_space").await {
            out.push(BaselineEvent {
                check: "aslr-enabled".into(),
                category: "system".into(),
                pass: val.trim() == "2",
                detail: val.trim().to_string(),
                severity: "high",
            });
        }

        // CIS 1.5.1 – Core dumps restricted
        if let Ok(val) = fs::read_to_string("/proc/sys/fs/suid_dumpable").await {
            out.push(BaselineEvent {
                check: "core-dumps-restricted".into(),
                category: "system".into(),
                pass: val.trim() == "0",
                detail: format!("suid_dumpable={}", val.trim()),
                severity: "medium",
            });
        }

        // ── Filesystem ───────────────────────────────────────

        // World-writable files in /etc
        let mut world_writable = Vec::new();
        if let Ok(mut entries) = fs::read_dir("/etc").await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                if let Ok(meta) = entry.metadata().await {
                    if meta.is_file() && meta.permissions().mode() & 0o002 != 0 {
                        world_writable.push(entry.path().to_string_lossy().to_string());
                    }
                }
            }
        }
        out.push(BaselineEvent {
            check: "no-world-writable-etc".into(),
            category: "filesystem".into(),
            pass: world_writable.is_empty(),
            detail: if world_writable.is_empty() {
                "none".into()
            } else {
                world_writable.join(", ")
            },
            severity: "high",
        });

        // CIS 1.1.2-1.1.5 – /tmp mount options
        if let Ok(mounts) = fs::read_to_string("/proc/mounts").await {
            if let Some(line) = mounts
                .lines()
                .find(|l| l.split_whitespace().nth(1) == Some("/tmp"))
            {
                let opts = line.split_whitespace().nth(3).unwrap_or("");
                out.push(BaselineEvent {
                    check: "tmp-noexec".into(),
                    category: "filesystem".into(),
                    pass: opts.contains("noexec"),
                    detail: opts.to_string(),
                    severity: "medium",
                });
                out.push(BaselineEvent {
                    check: "tmp-nosuid".into(),
                    category: "filesystem".into(),
                    pass: opts.contains("nosuid"),
                    detail: opts.to_string(),
                    severity: "medium",
                });
            }
        }
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
