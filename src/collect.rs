use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use sysinfo::{Networks, System};
use tokio::fs;
use tracing::{debug, warn};

use crate::events::*;

const MAX_PROCESS_EVENTS: usize = 4096;
const MAX_NETWORK_EVENTS: usize = 256;
const MAX_PROCESS_CMD_ARGS: usize = 64;
const MAX_PROCESS_CMD_BYTES: usize = 1024;
const MAX_PROCESS_NAME_BYTES: usize = 256;
const MAX_EVENT_STRING_BYTES: usize = 512;
const MAX_PATH_EVENT_BYTES: usize = 4096;
const MAX_BASELINE_EVENTS: usize = 32;
#[cfg(target_os = "linux")]
const MAX_WORLD_WRITABLE_PATHS: usize = 256;
#[cfg(target_os = "linux")]
const MAX_CONNECTION_EVENTS: usize = 65_536;
#[cfg(target_os = "linux")]
const MAX_LISTENER_EVENTS: usize = 16_384;
const MAX_FIM_PATHS_TRACKED: usize = 256;
const MAX_FIM_FILE_BYTES: u64 = 8 * 1024 * 1024;
const FIM_HASH_CHUNK_BYTES: usize = 8192;

#[derive(Debug)]
enum HashFileError {
    Io,
    MultipleHardLinks(u64),
    NonRegular,
    ReplacedDuringRead,
    Symlink,
    TooLarge(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileSnapshot {
    len: u64,
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    #[cfg(unix)]
    mtime: i64,
    #[cfg(unix)]
    mtime_nsec: i64,
    #[cfg(unix)]
    ctime: i64,
    #[cfg(unix)]
    ctime_nsec: i64,
}

#[derive(Clone, Debug)]
struct FimKnown {
    hash: String,
    snapshot: FileSnapshot,
}

impl FileSnapshot {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            Self {
                len: metadata.len(),
                dev: metadata.dev(),
                ino: metadata.ino(),
                mtime: metadata.mtime(),
                mtime_nsec: metadata.mtime_nsec(),
                ctime: metadata.ctime(),
                ctime_nsec: metadata.ctime_nsec(),
            }
        }
        #[cfg(not(unix))]
        {
            Self {
                len: metadata.len(),
            }
        }
    }
}

struct HashedFile {
    hash: String,
    size: u64,
    snapshot: FileSnapshot,
}

fn safe_telemetry_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric()
        || matches!(
            ch,
            ' ' | '/' | '.' | '_' | '-' | ':' | '@' | '+' | '=' | ',' | '[' | ']' | '(' | ')'
        )
}

fn push_sanitized_segment(out: &mut String, input: &str, max_bytes: usize) {
    for ch in input.chars() {
        if out.len() >= max_bytes {
            break;
        }
        let sanitized = if safe_telemetry_char(ch) { ch } else { '_' };
        if out.len() + sanitized.len_utf8() > max_bytes {
            break;
        }
        out.push(sanitized);
    }
}

fn sanitize_telemetry_string(input: &str, max_bytes: usize) -> String {
    let mut out = String::with_capacity(input.len().min(max_bytes));
    push_sanitized_segment(&mut out, input, max_bytes);
    out
}

fn sanitize_command_args(args: &[std::ffi::OsString]) -> String {
    let mut out = String::with_capacity(MAX_PROCESS_CMD_BYTES.min(128));
    for arg in args.iter().take(MAX_PROCESS_CMD_ARGS) {
        if !out.is_empty() {
            if out.len() >= MAX_PROCESS_CMD_BYTES {
                break;
            }
            out.push(' ');
        }
        push_sanitized_segment(&mut out, &arg.to_string_lossy(), MAX_PROCESS_CMD_BYTES);
    }
    out
}

fn open_fim_file(path: &Path) -> Result<(std::fs::File, FileSnapshot), HashFileError> {
    let path_metadata = std::fs::symlink_metadata(path).map_err(|_| HashFileError::Io)?;
    if path_metadata.file_type().is_symlink() {
        return Err(HashFileError::Symlink);
    }
    if !path_metadata.file_type().is_file() {
        return Err(HashFileError::NonRegular);
    }
    if path_metadata.len() > MAX_FIM_FILE_BYTES {
        return Err(HashFileError::TooLarge(path_metadata.len()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if path_metadata.nlink() > 1 {
            return Err(HashFileError::MultipleHardLinks(path_metadata.nlink()));
        }
    }

    let expected_snapshot = FileSnapshot::from_metadata(&path_metadata);
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }

    let file = options.open(path).map_err(|_| HashFileError::Io)?;
    let opened_metadata = file.metadata().map_err(|_| HashFileError::Io)?;
    if !opened_metadata.file_type().is_file() {
        return Err(HashFileError::NonRegular);
    }
    if opened_metadata.len() > MAX_FIM_FILE_BYTES {
        return Err(HashFileError::TooLarge(opened_metadata.len()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if opened_metadata.nlink() > 1 {
            return Err(HashFileError::MultipleHardLinks(opened_metadata.nlink()));
        }
    }
    let opened_snapshot = FileSnapshot::from_metadata(&opened_metadata);
    if opened_snapshot != expected_snapshot {
        return Err(HashFileError::ReplacedDuringRead);
    }

    Ok((file, opened_snapshot))
}

fn hash_file_limited_blocking(path: &Path) -> Result<HashedFile, HashFileError> {
    let (mut file, snapshot) = open_fim_file(path)?;
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; FIM_HASH_CHUNK_BYTES];

    loop {
        let read = file.read(&mut buffer).map_err(|_| HashFileError::Io)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or(HashFileError::TooLarge(u64::MAX))?;
        if total > MAX_FIM_FILE_BYTES {
            return Err(HashFileError::TooLarge(total));
        }
        hasher.update(&buffer[..read]);
    }

    let final_metadata = std::fs::symlink_metadata(path).map_err(|_| HashFileError::Io)?;
    if final_metadata.file_type().is_symlink() {
        return Err(HashFileError::Symlink);
    }
    if !final_metadata.file_type().is_file() {
        return Err(HashFileError::NonRegular);
    }
    if final_metadata.len() > MAX_FIM_FILE_BYTES {
        return Err(HashFileError::TooLarge(final_metadata.len()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if final_metadata.nlink() > 1 {
            return Err(HashFileError::MultipleHardLinks(final_metadata.nlink()));
        }
    }
    let final_snapshot = FileSnapshot::from_metadata(&final_metadata);
    if final_snapshot != snapshot {
        return Err(HashFileError::ReplacedDuringRead);
    }

    Ok(HashedFile {
        hash: format!("{:x}", hasher.finalize()),
        size: total,
        snapshot,
    })
}

async fn hash_file_limited(path: PathBuf) -> Result<HashedFile, HashFileError> {
    match tokio::task::spawn_blocking(move || hash_file_limited_blocking(&path)).await {
        Ok(result) => result,
        Err(_) => Err(HashFileError::Io),
    }
}

fn log_fim_hash_error(path: &str, err: HashFileError, context: &str) {
    match err {
        HashFileError::Io => {}
        HashFileError::MultipleHardLinks(nlink) => {
            warn!(path, nlink, "Skipping FIM {} for hard-linked file", context);
        }
        HashFileError::NonRegular => {
            warn!(path, "Skipping FIM {} for non-regular file", context);
        }
        HashFileError::ReplacedDuringRead => {
            warn!(
                path,
                "Skipping FIM {} because file identity changed during read", context
            );
        }
        HashFileError::Symlink => {
            warn!(path, "Skipping FIM {} for symlink path", context);
        }
        HashFileError::TooLarge(size) => {
            warn!(path, size, "Skipping FIM {} for oversized file", context);
        }
    }
}

/// Snapshot all running processes.
pub fn collect_processes(sys: &System) -> Vec<ProcessEvent> {
    let process_count = sys.processes().len();
    if process_count > MAX_PROCESS_EVENTS {
        warn!(
            count = process_count,
            cap = MAX_PROCESS_EVENTS,
            "process events capped to protect memory"
        );
    }

    let mut events = Vec::with_capacity(process_count.min(MAX_PROCESS_EVENTS));
    for (pid, process) in sys.processes().iter().take(MAX_PROCESS_EVENTS) {
        let exe = process
            .exe()
            .unwrap_or_else(|| std::path::Path::new(""))
            .to_string_lossy();

        let cmd_string = sanitize_command_args(process.cmd());
        let mut tokens = cmd_string.split_whitespace();
        let bin_name = tokens.next().unwrap_or("");

        // High-value signal: only record suspicious or anomalous processes.
        let is_suspicious = exe.starts_with("/tmp/")
            || exe.starts_with("/var/tmp/")
            || exe.starts_with("/dev/shm/")
            || exe.contains("/.") // hidden folder
            || bin_name == "curl"
            || bin_name == "wget"
            || bin_name == "nc"
            || bin_name == "netcat"
            || bin_name == "bash" && tokens.any(|t| t == "-i")
            || bin_name == "sh" && tokens.any(|t| t == "-i")
            || bin_name == "base64"
            || exe.is_empty() && !process.cmd().is_empty(); // Fileless execution / memfd

        if !is_suspicious {
            continue;
        }

        events.push(ProcessEvent {
            pid: pid.as_u32(),
            ppid: process.parent().map(|parent_pid| parent_pid.as_u32()),
            name: sanitize_telemetry_string(
                &process.name().to_string_lossy(),
                MAX_PROCESS_NAME_BYTES,
            ),
            cmd: sanitize_command_args(process.cmd()),
            user: process
                .user_id()
                .map(|user_id| {
                    sanitize_telemetry_string(&user_id.to_string(), MAX_EVENT_STRING_BYTES)
                })
                .unwrap_or_default(),
            cpu: process.cpu_usage(),
            mem_bytes: process.memory(),
        });
    }

    events
}

/// Snapshot network interface counters.
pub fn collect_network(networks: &Networks) -> Vec<NetworkEvent> {
    let network_count = networks.iter().count();
    if network_count > MAX_NETWORK_EVENTS {
        warn!(
            count = network_count,
            cap = MAX_NETWORK_EVENTS,
            "network events capped to protect memory"
        );
    }

    let mut events = Vec::with_capacity(network_count.min(MAX_NETWORK_EVENTS));
    for (name, data) in networks.iter().take(MAX_NETWORK_EVENTS) {
        events.push(NetworkEvent {
            iface: sanitize_telemetry_string(name, MAX_EVENT_STRING_BYTES),
            tx_bytes: data.total_transmitted(),
            rx_bytes: data.total_received(),
        });
    }

    events
}

// ── Connection & listener collectors (Linux /proc/net) ───────

#[cfg(target_os = "linux")]
mod procnet {
    use std::collections::HashMap;
    use std::io::BufRead;

    use super::{sanitize_telemetry_string, MAX_EVENT_STRING_BYTES, MAX_PROCESS_NAME_BYTES};

    const MAX_INODE_MAP_ENTRIES: usize = 65_536;
    const MAX_FDS_PER_PROCESS: usize = 4096;
    const MAX_PROC_NET_ROWS: usize = 65_536;

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
            return sanitize_telemetry_string(hex, MAX_EVENT_STRING_BYTES);
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
        let mut map = HashMap::with_capacity(MAX_INODE_MAP_ENTRIES.min(4096));
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
            let comm = sanitize_telemetry_string(&comm, MAX_PROCESS_NAME_BYTES);
            let fd_dir = format!("/proc/{}/fd", pid);
            let entries = match fs::read_dir(&fd_dir) {
                Ok(d) => d,
                Err(_) => continue,
            };
            for fd_entry in entries.flatten().take(MAX_FDS_PER_PROCESS) {
                if let Ok(link) = fs::read_link(fd_entry.path()) {
                    let link_str = link.to_string_lossy().to_string();
                    if let Some(inode_str) = link_str
                        .strip_prefix("socket:[")
                        .and_then(|s| s.strip_suffix(']'))
                    {
                        if let Ok(inode) = inode_str.parse::<u64>() {
                            map.insert(inode, (pid, comm.clone()));
                            if map.len() >= MAX_INODE_MAP_ENTRIES {
                                tracing::warn!(
                                    "inode map capped at {} entries to protect memory",
                                    MAX_INODE_MAP_ENTRIES
                                );
                                return map;
                            }
                        }
                    }
                }
            }
        }
        map
    }

    /// Parse a /proc/net/{tcp,tcp6,udp,udp6} file.
    pub fn parse_proc_net(path: &str, is_ipv6: bool) -> Vec<RawConnection> {
        let file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(_) => return Vec::with_capacity(0),
        };
        let reader = std::io::BufReader::new(file);
        let mut conns = Vec::with_capacity(MAX_PROC_NET_ROWS.min(1024));
        for line in reader.lines().skip(1).take(MAX_PROC_NET_ROWS) {
            let line = match line {
                Ok(line) => line,
                Err(_) => continue,
            };
            let mut iter = line.split_whitespace();
            let _sl = match iter.next() {
                Some(s) => s,
                None => continue,
            }; // [0]
            let local_field = match iter.next() {
                Some(s) => s,
                None => continue,
            }; // [1]
            let remote_field = match iter.next() {
                Some(s) => s,
                None => continue,
            }; // [2]
            let state_hex = match iter.next() {
                Some(s) => s,
                None => continue,
            }; // [3]
               // Skip fields [4]–[8] to reach [9] (inode)
            let inode_str = match iter.nth(5) {
                Some(s) => s,
                None => continue,
            }; // [9]

            let (local_addr_hex, local_port_hex) = match local_field.rsplit_once(':') {
                Some(pair) => pair,
                None => continue,
            };
            let (remote_addr_hex, remote_port_hex) = match remote_field.rsplit_once(':') {
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
                state: tcp_state(state_hex),
                inode: inode_str.parse().unwrap_or(0),
            });
        }
        conns
    }
}

/// Snapshot all active TCP/UDP connections with PID resolution (Linux).
#[cfg(target_os = "linux")]
pub fn collect_connections() -> Vec<ConnectionEvent> {
    let inode_map = procnet::build_inode_map();
    let mut events = Vec::with_capacity(MAX_CONNECTION_EVENTS.min(1024));
    let sources = [
        ("/proc/net/tcp", "tcp", false),
        ("/proc/net/tcp6", "tcp6", true),
        ("/proc/net/udp", "udp", false),
        ("/proc/net/udp6", "udp6", true),
    ];
    for (path, protocol, is_ipv6) in &sources {
        for conn in procnet::parse_proc_net(path, *is_ipv6) {
            if events.len() >= MAX_CONNECTION_EVENTS {
                warn!(
                    "connection events capped at {} entries to protect memory",
                    MAX_CONNECTION_EVENTS
                );
                return events;
            }
            let (pid, process_name) = inode_map
                .get(&conn.inode)
                .map(|(p, n)| (Some(*p), Some(n.clone())))
                .unwrap_or((None, None));
            events.push(ConnectionEvent {
                protocol,
                local_addr: conn.local_addr,
                local_port: conn.local_port,
                remote_addr: conn.remote_addr,
                remote_port: conn.remote_port,
                state: conn.state,
                pid,
                process_name,
            });
        }
    }
    events
}

#[cfg(not(target_os = "linux"))]
pub fn collect_connections() -> Vec<ConnectionEvent> {
    Vec::with_capacity(0)
}

/// Snapshot all listening network sockets with PID resolution (Linux).
#[cfg(target_os = "linux")]
pub fn collect_listeners() -> Vec<ListenerEvent> {
    let inode_map = procnet::build_inode_map();
    let mut events = Vec::with_capacity(MAX_LISTENER_EVENTS.min(1024));
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
            if events.len() >= MAX_LISTENER_EVENTS {
                warn!(
                    "listener events capped at {} entries to protect memory",
                    MAX_LISTENER_EVENTS
                );
                return events;
            }
            let (pid, process_name) = inode_map
                .get(&conn.inode)
                .map(|(p, n)| (Some(*p), Some(n.clone())))
                .unwrap_or((None, None));
            events.push(ListenerEvent {
                protocol,
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
    Vec::with_capacity(0)
}

/// Starts a push-based File Integrity Monitoring (FIM) watcher.
pub fn start_fim_monitor(paths: Vec<String>) -> tokio::sync::mpsc::Receiver<FimEvent> {
    use notify::{EventKind, RecursiveMode, Watcher};

    let (tx, rx) = tokio::sync::mpsc::channel(100);

    tokio::spawn(async move {
        let mut tracked_paths = Vec::with_capacity(paths.len().min(MAX_FIM_PATHS_TRACKED));
        for path in paths.into_iter().take(MAX_FIM_PATHS_TRACKED) {
            tracked_paths.push(path);
        }
        let mut known: HashMap<String, FimKnown> = HashMap::with_capacity(tracked_paths.len());
        let mut watched_paths = HashSet::with_capacity(tracked_paths.len());
        for path in &tracked_paths {
            watched_paths.insert(path.clone());
        }

        // Baseline initial hashes
        for path_str in &tracked_paths {
            let path = Path::new(path_str);
            match hash_file_limited(path.to_path_buf()).await {
                Ok(hashed) => {
                    known.insert(
                        path_str.clone(),
                        FimKnown {
                            hash: hashed.hash,
                            snapshot: hashed.snapshot,
                        },
                    );
                }
                Err(err) => log_fim_hash_error(path_str, err, "baseline hash"),
            }
        }

        let (notify_tx, notify_rx) = flume::bounded(256);

        let mut watcher = match notify::recommended_watcher(move |res| {
            if let Ok(event) = res {
                let _ = notify_tx.send(event);
            }
        }) {
            Ok(w) => w,
            Err(e) => {
                warn!(err = %e, "Failed to start FIM watcher");
                return;
            }
        };

        for path_str in &tracked_paths {
            let path = Path::new(path_str);
            if let Err(e) = watcher.watch(path, RecursiveMode::NonRecursive) {
                warn!(path = path_str, err = %e, "Failed to watch FIM path");
            } else {
                debug!(path = path_str, "Watching FIM path");
            }
        }

        // Keep running and process async events
        while let Ok(event) = notify_rx.recv_async().await {
            // We only care about data modification, creation, or deletion
            let is_relevant = matches!(
                event.kind,
                EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)
            );

            if !is_relevant {
                continue;
            }

            for path in event.paths {
                let path_str = path.to_string_lossy().to_string();
                if !watched_paths.contains(&path_str) {
                    continue;
                }
                let display_path = sanitize_telemetry_string(&path_str, MAX_PATH_EVENT_BYTES);

                match hash_file_limited(path.clone()).await {
                    Ok(hashed) => {
                        let prev = known.get(&path_str).cloned();
                        let prev_sha256 = prev.as_ref().map(|entry| entry.hash.clone());
                        let change = match &prev {
                            Some(old)
                                if old.hash != hashed.hash || old.snapshot != hashed.snapshot =>
                            {
                                "modified"
                            }
                            None => "created",
                            _ => continue, // Unchanged hash
                        };

                        debug!(path = %path_str, change, "FIM event");
                        let _ = tx
                            .send(FimEvent {
                                path: display_path,
                                sha256: hashed.hash.clone(),
                                prev_sha256,
                                change,
                                size: hashed.size,
                            })
                            .await;

                        known.insert(
                            path_str,
                            FimKnown {
                                hash: hashed.hash,
                                snapshot: hashed.snapshot,
                            },
                        );
                    }
                    Err(
                        err @ (HashFileError::MultipleHardLinks(_)
                        | HashFileError::NonRegular
                        | HashFileError::ReplacedDuringRead
                        | HashFileError::Symlink
                        | HashFileError::TooLarge(_)),
                    ) => log_fim_hash_error(&path_str, err, "event"),
                    Err(HashFileError::Io) => {
                        // Emit deletion only when the file no longer exists.
                        if fs::metadata(&path).await.is_err() {
                            if let Some(prev_hash) = known.remove(&path_str) {
                                warn!(path = %path_str, "Watched file deleted");
                                let _ = tx
                                    .send(FimEvent {
                                        path: display_path,
                                        sha256: String::new(),
                                        prev_sha256: Some(prev_hash.hash),
                                        change: "deleted",
                                        size: 0,
                                    })
                                    .await;
                            }
                        }
                    }
                }
            }
        }

        // Ensure watcher is not dropped
        drop(watcher);
    });

    rx
}

/// Run security baseline checks (CIS-style, 15 checks).
pub async fn check_baseline() -> Vec<BaselineEvent> {
    #[allow(unused_mut)]
    let mut out = Vec::with_capacity(MAX_BASELINE_EVENTS);

    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::PermissionsExt;

        // ── Authentication ───────────────────────────────────

        // CIS 6.1.3 – /etc/shadow permissions
        if let Ok(m) = fs::metadata("/etc/shadow").await {
            let mode = m.permissions().mode();
            out.push(BaselineEvent {
                check: "shadow-perms",
                category: "auth",
                pass: mode & 0o077 == 0,
                detail: format!("{:o}", mode),
                severity: "high",
            });
        }

        // CIS 6.1.2 – /etc/passwd permissions
        if let Ok(m) = fs::metadata("/etc/passwd").await {
            let mode = m.permissions().mode();
            out.push(BaselineEvent {
                check: "passwd-perms",
                category: "auth",
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
                check: "password-max-age",
                category: "auth",
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
                check: "ssh-no-root",
                category: "auth",
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
                check: "ssh-max-auth-tries",
                category: "auth",
                pass: max_auth.map_or(false, |n| n <= 4),
                detail: max_auth.map_or("not set".into(), |n| n.to_string()),
                severity: "medium",
            });

            // CIS 5.2.11 – SSH PermitEmptyPasswords
            let no_empty = sshd
                .lines()
                .any(|l| l.trim().eq_ignore_ascii_case("PermitEmptyPasswords no"));
            out.push(BaselineEvent {
                check: "ssh-no-empty-passwords",
                category: "auth",
                pass: no_empty,
                detail: "PermitEmptyPasswords".into(),
                severity: "high",
            });
        }

        // ── Network kernel parameters ────────────────────────

        // CIS 3.1.1 – IP forwarding
        if let Ok(val) = fs::read_to_string("/proc/sys/net/ipv4/ip_forward").await {
            out.push(BaselineEvent {
                check: "ip-forwarding-disabled",
                category: "network",
                pass: val.trim() == "0",
                detail: val.trim().to_string(),
                severity: "medium",
            });
        }

        // CIS 3.2.8 – TCP SYN cookies
        if let Ok(val) = fs::read_to_string("/proc/sys/net/ipv4/tcp_syncookies").await {
            out.push(BaselineEvent {
                check: "syn-cookies-enabled",
                category: "network",
                pass: val.trim() == "1",
                detail: val.trim().to_string(),
                severity: "medium",
            });
        }

        // CIS 3.2.2 – ICMP redirects
        if let Ok(val) = fs::read_to_string("/proc/sys/net/ipv4/conf/all/accept_redirects").await {
            out.push(BaselineEvent {
                check: "icmp-redirects-disabled",
                category: "network",
                pass: val.trim() == "0",
                detail: val.trim().to_string(),
                severity: "medium",
            });
        }

        // CIS 3.2.1 – Source routing
        if let Ok(val) = fs::read_to_string("/proc/sys/net/ipv4/conf/all/accept_source_route").await
        {
            out.push(BaselineEvent {
                check: "source-route-disabled",
                category: "network",
                pass: val.trim() == "0",
                detail: val.trim().to_string(),
                severity: "medium",
            });
        }

        // ── System hardening ─────────────────────────────────

        // CIS 1.5.3 – ASLR
        if let Ok(val) = fs::read_to_string("/proc/sys/kernel/randomize_va_space").await {
            out.push(BaselineEvent {
                check: "aslr-enabled",
                category: "system",
                pass: val.trim() == "2",
                detail: val.trim().to_string(),
                severity: "high",
            });
        }

        // CIS 1.5.1 – Core dumps restricted
        if let Ok(val) = fs::read_to_string("/proc/sys/fs/suid_dumpable").await {
            out.push(BaselineEvent {
                check: "core-dumps-restricted",
                category: "system",
                pass: val.trim() == "0",
                detail: format!("suid_dumpable={}", val.trim()),
                severity: "medium",
            });
        }

        // ── Filesystem ───────────────────────────────────────

        // World-writable files in /etc
        let mut world_writable = Vec::with_capacity(MAX_WORLD_WRITABLE_PATHS.min(16));
        if let Ok(mut entries) = fs::read_dir("/etc").await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                if let Ok(meta) = entry.metadata().await {
                    if meta.is_file() && meta.permissions().mode() & 0o002 != 0 {
                        if world_writable.len() < MAX_WORLD_WRITABLE_PATHS {
                            world_writable.push(sanitize_telemetry_string(
                                &entry.path().to_string_lossy(),
                                MAX_PATH_EVENT_BYTES,
                            ));
                        }
                    }
                }
            }
        }
        out.push(BaselineEvent {
            check: "no-world-writable-etc",
            category: "filesystem",
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
                    check: "tmp-noexec",
                    category: "filesystem",
                    pass: opts.contains("noexec"),
                    detail: opts.to_string(),
                    severity: "medium",
                });
                out.push(BaselineEvent {
                    check: "tmp-nosuid",
                    category: "filesystem",
                    pass: opts.contains("nosuid"),
                    detail: opts.to_string(),
                    severity: "medium",
                });
            }
            
            // Read-Only Root Filesystem check
            if let Some(line) = mounts
                .lines()
                .find(|l| l.split_whitespace().nth(1) == Some("/"))
            {
                let opts = line.split_whitespace().nth(3).unwrap_or("");
                out.push(BaselineEvent {
                    check: "root-ro",
                    category: "filesystem",
                    pass: opts.starts_with("ro,") || opts == "ro",
                    detail: opts.to_string(),
                    severity: "critical",
                });
            }
        }
        
        // ── Firewall configuration ───────────────────────────
        
        let mut fw_active = false;
        let mut fw_detail = String::new();
        
        if let Ok(ip_tables) = fs::read_to_string("/proc/net/ip_tables_names").await {
            if !ip_tables.trim().is_empty() {
                fw_active = true;
                fw_detail.push_str("iptables ");
            }
        }
        if let Ok(ip6_tables) = fs::read_to_string("/proc/net/ip6_tables_names").await {
            if !ip6_tables.trim().is_empty() {
                fw_active = true;
                fw_detail.push_str("ip6tables ");
            }
        }
        
        out.push(BaselineEvent {
            check: "firewall-active",
            category: "network",
            pass: fw_active,
            detail: if fw_active { fw_detail.trim().to_string() } else { "none".to_string() },
            severity: "high",
        });
    }

    out
}

/// Snapshot kernel security state.
pub async fn collect_kernel() -> Option<KernelEvent> {
    #[cfg(target_os = "linux")]
    {
        let secure_boot = fs::metadata(
            "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ba-11d2-aa5d-00e098032b8c",
        )
        .await
        .is_ok();

        let lockdown_content = fs::read_to_string("/sys/kernel/security/lockdown")
            .await
            .unwrap_or_default();
        let lockdown = if lockdown_content.contains("[integrity]") {
            "integrity".into()
        } else if lockdown_content.contains("[confidentiality]") {
            "confidentiality".into()
        } else if lockdown_content.contains("[none]") {
            "none".into()
        } else {
            "unknown".into()
        };

        let modules_disabled = fs::read_to_string("/proc/sys/kernel/modules_disabled")
            .await
            .unwrap_or_default()
            .trim()
            == "1";

        let kexec_disabled = fs::read_to_string("/proc/sys/kernel/kexec_load_disabled")
            .await
            .unwrap_or_default()
            .trim()
            == "1";

        let bpf_disabled_content = fs::read_to_string("/proc/sys/kernel/unprivileged_bpf_disabled")
            .await
            .unwrap_or_default();
        let bpf_disabled = bpf_disabled_content.trim() == "1" || bpf_disabled_content.trim() == "2";

        let tainted = fs::read_to_string("/proc/sys/kernel/tainted")
            .await
            .unwrap_or_default()
            .trim()
            .parse::<u32>()
            .unwrap_or(0);

        let module_count = if let Ok(modules) = fs::read_to_string("/proc/modules").await {
            modules.lines().count()
        } else {
            0
        };

        Some(KernelEvent {
            secure_boot,
            lockdown,
            modules_disabled,
            kexec_disabled,
            unprivileged_bpf_disabled: bpf_disabled,
            tainted,
            module_count,
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    // ── procnet parser tests (Linux-only but pure logic) ─────────────

    #[cfg(target_os = "linux")]
    mod procnet_tests {
        use super::super::procnet;

        #[test]
        fn parse_ipv4_loopback() {
            // 0100007F = 127.0.0.1 in little-endian /proc format
            assert_eq!(procnet::parse_ipv4("0100007F"), "127.0.0.1");
        }

        #[test]
        fn parse_ipv4_zeros() {
            assert_eq!(procnet::parse_ipv4("00000000"), "0.0.0.0");
        }

        #[test]
        fn parse_ipv4_broadcast() {
            // FFFFFFFF = 255.255.255.255
            assert_eq!(procnet::parse_ipv4("FFFFFFFF"), "255.255.255.255");
        }

        #[test]
        fn parse_ipv4_typical_addr() {
            // C0A80164 = 192.168.1.100 in network order, but /proc stores little-endian:
            // 192.168.1.100 → 0x6401A8C0
            assert_eq!(procnet::parse_ipv4("6401A8C0"), "192.168.1.100");
        }

        #[test]
        fn parse_ipv4_invalid_hex_returns_zeros() {
            assert_eq!(procnet::parse_ipv4("ZZZZZZZZ"), "0.0.0.0");
        }

        #[test]
        fn parse_ipv6_loopback() {
            // ::1 in /proc/net/tcp6 format (little-endian per 32-bit group)
            assert_eq!(
                procnet::parse_ipv6("00000000000000000000000001000000"),
                "::1"
            );
        }

        #[test]
        fn parse_ipv6_all_zeros() {
            assert_eq!(
                procnet::parse_ipv6("00000000000000000000000000000000"),
                "::"
            );
        }

        #[test]
        fn parse_ipv6_wrong_length_returns_input() {
            assert_eq!(procnet::parse_ipv6("SHORT"), "SHORT");
            assert_eq!(procnet::parse_ipv6(""), "");
        }

        #[test]
        fn parse_port_common_values() {
            assert_eq!(procnet::parse_port("0050"), 80);
            assert_eq!(procnet::parse_port("01BB"), 443);
            assert_eq!(procnet::parse_port("0016"), 22);
            assert_eq!(procnet::parse_port("0000"), 0);
            assert_eq!(procnet::parse_port("FFFF"), 65535);
        }

        #[test]
        fn parse_port_invalid_hex_returns_zero() {
            assert_eq!(procnet::parse_port("ZZZZ"), 0);
        }

        #[test]
        fn tcp_state_all_known_states() {
            assert_eq!(procnet::tcp_state("01"), "ESTABLISHED");
            assert_eq!(procnet::tcp_state("02"), "SYN_SENT");
            assert_eq!(procnet::tcp_state("03"), "SYN_RECV");
            assert_eq!(procnet::tcp_state("04"), "FIN_WAIT1");
            assert_eq!(procnet::tcp_state("05"), "FIN_WAIT2");
            assert_eq!(procnet::tcp_state("06"), "TIME_WAIT");
            assert_eq!(procnet::tcp_state("07"), "CLOSE");
            assert_eq!(procnet::tcp_state("08"), "CLOSE_WAIT");
            assert_eq!(procnet::tcp_state("09"), "LAST_ACK");
            assert_eq!(procnet::tcp_state("0A"), "LISTEN");
            assert_eq!(procnet::tcp_state("0B"), "CLOSING");
        }

        #[test]
        fn tcp_state_unknown_value() {
            assert_eq!(procnet::tcp_state("FF"), "UNKNOWN");
            assert_eq!(procnet::tcp_state("00"), "UNKNOWN");
            assert_eq!(procnet::tcp_state("ZZ"), "UNKNOWN");
        }

        #[test]
        fn parse_proc_net_nonexistent_file_returns_empty() {
            let result = procnet::parse_proc_net("/tmp/igel_nonexistent_file_83724", false);
            assert!(result.is_empty());
        }

        #[test]
        fn parse_proc_net_tcp_format() {
            // Write a synthetic /proc/net/tcp file
            let content = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0";
            let path = std::env::temp_dir().join("igel_test_proc_net_tcp");
            std::fs::write(&path, content).expect("write");

            let conns = procnet::parse_proc_net(path.to_str().expect("path"), false);
            assert_eq!(conns.len(), 1);
            assert_eq!(conns[0].local_addr, "127.0.0.1");
            assert_eq!(conns[0].local_port, 3306); // 0x0CEA
            assert_eq!(conns[0].remote_addr, "0.0.0.0");
            assert_eq!(conns[0].remote_port, 0);
            assert_eq!(conns[0].state, "LISTEN"); // 0x0A
            assert_eq!(conns[0].inode, 12345);

            std::fs::remove_file(&path).ok();
        }

        #[test]
        fn parse_proc_net_skips_malformed_lines() {
            let content = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   BAD LINE
   0: 0100007F:0050 00000000:0000 01 00000000:00000000 00:00000000 00000000     0        0 99 1 0000000000000000 100 0 0 10 0";
            let path = std::env::temp_dir().join("igel_test_proc_net_malformed");
            std::fs::write(&path, content).expect("write");

            let conns = procnet::parse_proc_net(path.to_str().expect("path"), false);
            // Malformed line is skipped, valid line parsed
            assert_eq!(conns.len(), 1);
            assert_eq!(conns[0].local_port, 80);

            std::fs::remove_file(&path).ok();
        }
    }

    // ── Cross-platform tests ─────────────────────────────────────────

    #[test]
    fn collect_processes_returns_nonempty() {
        let mut sys = System::new_all();
        sys.refresh_all();
        let procs = collect_processes(&sys);
        assert!(
            !procs.is_empty(),
            "there should be at least one process running"
        );
    }

    #[test]
    fn collect_processes_does_not_panic() {
        let mut sys = System::new_all();
        sys.refresh_all();
        let _procs = collect_processes(&sys);
    }

    #[test]
    fn collect_network_returns_results() {
        let mut networks = sysinfo::Networks::new_with_refreshed_list();
        networks.refresh(true);
        let net = collect_network(&networks);
        // Most systems have at least one network interface (lo/loopback)
        // but don't make this a hard requirement—just verify types
        for iface in &net {
            assert!(!iface.iface.is_empty());
        }
    }

    #[test]
    fn telemetry_sanitizer_removes_control_and_parser_metacharacters() {
        let sanitized = sanitize_telemetry_string("proc\n${jndi:ldap://x}\u{202e}", 128);

        assert!(!sanitized.contains('\n'));
        assert!(!sanitized.contains('$'));
        assert!(!sanitized.contains('{'));
        assert!(!sanitized.contains('}'));
        assert!(sanitized.contains("jndi:ldap://x"));
    }

    #[test]
    fn telemetry_sanitizer_enforces_byte_cap() {
        let sanitized = sanitize_telemetry_string("abcdef", 3);

        assert_eq!(sanitized, "abc");
    }

    #[test]
    fn fim_hash_streams_small_file() {
        let path = std::env::temp_dir().join("igel_test_fim_hash_small");
        std::fs::write(&path, b"abc").expect("write");

        let hashed = hash_file_limited_blocking(&path).expect("hash");

        assert_eq!(hashed.size, 3);
        assert_eq!(
            hashed.hash,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn fim_hash_rejects_oversized_file() {
        let path = std::env::temp_dir().join("igel_test_fim_hash_oversized");
        let file = std::fs::File::create(&path).expect("create");
        file.set_len(MAX_FIM_FILE_BYTES + 1).expect("set length");

        let result = hash_file_limited_blocking(&path);

        assert!(matches!(result, Err(HashFileError::TooLarge(size)) if size > MAX_FIM_FILE_BYTES));

        std::fs::remove_file(&path).ok();
    }

    #[cfg(unix)]
    #[test]
    fn fim_hash_rejects_symlink_path() {
        let target = std::env::temp_dir().join("igel_test_fim_hash_symlink_target");
        let link = std::env::temp_dir().join("igel_test_fim_hash_symlink_link");
        std::fs::write(&target, b"abc").expect("write");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        let result = hash_file_limited_blocking(&link);

        assert!(matches!(result, Err(HashFileError::Symlink)));

        std::fs::remove_file(&link).ok();
        std::fs::remove_file(&target).ok();
    }

    #[cfg(unix)]
    #[test]
    fn fim_hash_rejects_hard_linked_file() {
        let original = std::env::temp_dir().join("igel_test_fim_hash_hardlink_original");
        let linked = std::env::temp_dir().join("igel_test_fim_hash_hardlink_linked");
        std::fs::write(&original, b"abc").expect("write");
        let _ = std::fs::remove_file(&linked);
        std::fs::hard_link(&original, &linked).expect("hard link");

        let result = hash_file_limited_blocking(&original);

        assert!(matches!(result, Err(HashFileError::MultipleHardLinks(nlink)) if nlink > 1));

        std::fs::remove_file(&linked).ok();
        std::fs::remove_file(&original).ok();
    }

    #[test]
    fn heartbeat_captures_system_info() {
        let mut sys = System::new_all();
        sys.refresh_all();
        let hb = heartbeat(&sys, 42);

        assert_eq!(hb.events_sent, 42);
        assert!(
            hb.mem_pct >= 0.0 && hb.mem_pct <= 100.0,
            "mem_pct out of range: {}",
            hb.mem_pct
        );
        assert!(hb.cpu >= 0.0, "cpu must be non-negative");
    }

    #[test]
    fn heartbeat_serializes_to_json() {
        let mut sys = System::new_all();
        sys.refresh_all();
        let hb = heartbeat(&sys, 0);
        let json = serde_json::to_value(&hb).expect("serialize");

        assert!(json["os"].is_string());
        assert!(json["os_version"].is_string());
        assert!(json["uptime_secs"].is_u64());
        assert_eq!(json["events_sent"], 0);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_connections_returns_empty() {
        assert!(collect_connections().is_empty());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_listeners_returns_empty() {
        assert!(collect_listeners().is_empty());
    }
}
