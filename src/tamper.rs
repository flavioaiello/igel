use serde::Serialize;
use std::fs;

pub const MAX_PIDS_CHECKED: usize = 8192;
const MAX_TAMPER_EVENTS: usize = 1024;
const MAX_TAMPER_DETAIL_BYTES: usize = 512;

#[derive(Debug, Serialize)]
pub struct TamperEvent {
    pub category: &'static str,
    pub signal: &'static str,
    pub severity: &'static str,
    pub detail: String,
}

fn push_event(evs: &mut Vec<TamperEvent>, event: TamperEvent) {
    if evs.len() < MAX_TAMPER_EVENTS {
        evs.push(event);
    }
}

fn mount_is_rw(options: &str) -> bool {
    options.split(',').any(|opt| opt.trim() == "rw")
}

fn sanitize_detail(input: &str) -> String {
    let mut out = String::with_capacity(input.len().min(MAX_TAMPER_DETAIL_BYTES));
    for ch in input.chars() {
        if out.len() >= MAX_TAMPER_DETAIL_BYTES {
            break;
        }
        let sanitized = if ch.is_ascii_alphanumeric()
            || matches!(
                ch,
                ' ' | '/' | '.' | '_' | '-' | ':' | '@' | '+' | '=' | ',' | '[' | ']' | '(' | ')'
            ) {
            ch
        } else {
            '_'
        };
        if out.len() + sanitized.len_utf8() > MAX_TAMPER_DETAIL_BYTES {
            break;
        }
        out.push(sanitized);
    }
    out
}

pub fn check_tampering(pids: &[u32]) -> Vec<TamperEvent> {
    let mut evs = Vec::with_capacity(MAX_TAMPER_EVENTS.min(16));
    for pid in pids.iter().take(MAX_PIDS_CHECKED) {
        if let Ok(st) = fs::read_to_string(format!("/proc/{}/status", pid)) {
            for ln in st.lines() {
                if ln.starts_with("TracerPid:") {
                    let mut parts = ln.split_whitespace();
                    let _key = parts.next();
                    if let Some(val) = parts.next() {
                        if val != "0" && parts.next().is_none() {
                            push_event(
                                &mut evs,
                                TamperEvent {
                                    category: "process_injection",
                                    signal: "active_ptrace",
                                    severity: "critical",
                                    detail: sanitize_detail(&format!(
                                        "PID {} traced by {}",
                                        pid, val
                                    )),
                                },
                            );
                        }
                    }
                    break;
                }
            }
        }
    }
    if let Ok(st) = fs::read_to_string("/proc/sys/kernel/tainted") {
        if let Ok(v) = st.trim().parse::<u32>() {
            if v != 0 {
                push_event(
                    &mut evs,
                    TamperEvent {
                        category: "kernel_tampering",
                        signal: "kernel_tainted",
                        severity: "high",
                        detail: sanitize_detail(&format!("Taint: {}", v)),
                    },
                );
            }
        }
    }
    if let Ok(st) = fs::read_to_string("/proc/mounts") {
        for ln in st.lines() {
            let mut parts = ln.split_whitespace();
            let _dev = match parts.next() {
                Some(d) => d,
                None => continue,
            };
            let mount_point = match parts.next() {
                Some(m) => m,
                None => continue,
            };
            let _fs_type = parts.next();
            let options = match parts.next() {
                Some(o) => o,
                None => continue,
            };
            let critical_mount = mount_point == "/"
                || mount_point.starts_with("/usr")
                || mount_point.starts_with("/bin");
            if critical_mount && mount_is_rw(options) {
                push_event(
                    &mut evs,
                    TamperEvent {
                        category: "fs_forcing",
                        signal: "unauthorized_rw",
                        severity: "critical",
                        detail: sanitize_detail(&format!("Mount {} is rw", mount_point)),
                    },
                );
            }
        }
    }
    evs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tamper_event_serializes_correctly() {
        let ev = TamperEvent {
            category: "process_injection",
            signal: "active_ptrace",
            severity: "critical",
            detail: "PID 100 traced by 200".into(),
        };
        let v = serde_json::to_value(&ev).expect("serialize");
        assert_eq!(v["category"], "process_injection");
        assert_eq!(v["signal"], "active_ptrace");
        assert_eq!(v["severity"], "critical");
        assert_eq!(v["detail"], "PID 100 traced by 200");
    }

    #[test]
    fn tamper_event_all_categories() {
        let categories = [
            ("process_injection", "active_ptrace", "critical"),
            ("kernel_tampering", "kernel_tainted", "high"),
            ("fs_forcing", "unauthorized_rw", "critical"),
        ];
        for (cat, sig, sev) in categories {
            let ev = TamperEvent {
                category: cat,
                signal: sig,
                severity: sev,
                detail: "test".into(),
            };
            let v = serde_json::to_value(&ev).expect("serialize");
            assert_eq!(v["category"], cat);
            assert_eq!(v["signal"], sig);
            assert_eq!(v["severity"], sev);
        }
    }

    /// Test the mount-line parsing logic in isolation by emulating
    /// the same condition used in check_tampering.
    #[test]
    fn mount_rw_detection_logic() {
        let mount_lines = [
            "rootfs / rootfs rw,relatime 0 0",    // rw root → should trigger
            "proc /proc proc rw,nosuid 0 0",      // /proc → not a critical path
            "sysfs /sys sysfs ro,relatime 0 0",   // ro → safe
            "/dev/sda1 /usr ext4 rw,noatime 0 0", // /usr rw → should trigger
            "/dev/sda2 /bin ext4 rw,nosuid 0 0",  // /bin rw → should trigger
            "/dev/sda3 /home ext4 rw,nosuid 0 0", // /home → not a critical path
        ];

        let mut flagged = Vec::new();
        for ln in &mount_lines {
            let mut parts = ln.split_whitespace();
            let _dev = match parts.next() {
                Some(d) => d,
                None => continue,
            };
            let mount_point = match parts.next() {
                Some(m) => m,
                None => continue,
            };
            let _fs_type = parts.next();
            let options = match parts.next() {
                Some(o) => o,
                None => continue,
            };
            let critical_mount = mount_point == "/"
                || mount_point.starts_with("/usr")
                || mount_point.starts_with("/bin");
            if critical_mount && mount_is_rw(options) {
                flagged.push(mount_point.to_string());
            }
        }

        assert!(
            flagged.contains(&"/".to_string()),
            "root rw mount not detected"
        );
        assert!(
            flagged.contains(&"/usr".to_string()),
            "/usr rw mount not detected"
        );
        assert!(
            flagged.contains(&"/bin".to_string()),
            "/bin rw mount not detected"
        );
        assert_eq!(
            flagged.len(),
            3,
            "expected exactly 3 flagged mounts, got: {:?}",
            flagged
        );
    }

    /// Test TracerPid parsing logic in isolation.
    #[test]
    fn tracer_pid_parsing_logic() {
        let status_content = "\
Name:\tsshd
Umask:\t0022
State:\tS (sleeping)
Tgid:\t1234
Pid:\t1234
PPid:\t1
TracerPid:\t5678
Uid:\t0\t0\t0\t0";

        let mut tracer_found = false;
        for ln in status_content.lines() {
            if ln.starts_with("TracerPid:") {
                let mut parts = ln.split_whitespace();
                let _key = parts.next();
                if let Some(val) = parts.next() {
                    if val != "0" && parts.next().is_none() {
                        tracer_found = true;
                        assert_eq!(val, "5678");
                    }
                }
                break;
            }
        }
        assert!(tracer_found, "TracerPid should have been detected");
    }

    /// Verify that TracerPid 0 (no tracer) is not flagged.
    #[test]
    fn tracer_pid_zero_not_flagged() {
        let status_content = "TracerPid:\t0";

        let mut flagged = false;
        for ln in status_content.lines() {
            if ln.starts_with("TracerPid:") {
                let mut parts = ln.split_whitespace();
                let _key = parts.next();
                if let Some(val) = parts.next() {
                    if val != "0" && parts.next().is_none() {
                        flagged = true;
                    }
                }
                break;
            }
        }
        assert!(!flagged, "TracerPid 0 should not be flagged");
    }

    #[test]
    fn mount_rw_option_without_trailing_comma_detected() {
        assert!(mount_is_rw("rw"));
        assert!(mount_is_rw("rw,nosuid,nodev"));
        assert!(!mount_is_rw("ro,nosuid,nodev"));
    }

    #[test]
    fn tamper_detail_sanitizer_removes_control_characters() {
        let sanitized = sanitize_detail("Mount /tmp/evil\n${jndi:ldap://x} is rw");

        assert!(!sanitized.contains('\n'));
        assert!(!sanitized.contains('$'));
        assert!(!sanitized.contains('{'));
        assert!(!sanitized.contains('}'));
        assert!(sanitized.contains("jndi:ldap://x"));
    }

    /// Test kernel taint parsing logic.
    #[test]
    fn kernel_taint_parsing() {
        // Non-zero taint value should be flagged
        let taint_str = "4096\n";
        let v = taint_str.trim().parse::<u32>().unwrap();
        assert_ne!(v, 0);

        // Zero taint → clean
        let clean = "0\n";
        let v = clean.trim().parse::<u32>().unwrap();
        assert_eq!(v, 0);
    }
}
