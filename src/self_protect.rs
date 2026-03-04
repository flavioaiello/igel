//! Igel self-protection: process hardening and Landlock filesystem sandboxing.
//!
//! **Phase 1** (`harden_process`): disables core dumps via `prctl`.
//! **Phase 2** (`sandbox_filesystem`): applies a Landlock LSM sandbox that
//! restricts filesystem access to explicitly allowed paths.  On kernels
//! without Landlock (< 5.13) this degrades gracefully to a no-op.

// ── Phase 1: Process hardening ───────────────────────────────────────────────

/// Disable core dumps and restrict ptrace.  Called early, before config load.
#[cfg(target_os = "linux")]
pub fn harden_process() {
    // SAFETY: `prctl(PR_SET_DUMPABLE, 0)` is a well-defined Linux syscall
    // accepting five scalar (integer) arguments.  Setting DUMPABLE to 0
    // prevents core dumps and restricts `ptrace` attachment by non-root
    // processes.  All arguments are compile-time constants — no pointer
    // dereference, no memory corruption risk.  Returns 0 on success, -1 on
    // failure (with errno set).
    unsafe {
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) == 0 {
            tracing::info!("self-protection: core dumps disabled (PR_SET_DUMPABLE=0)");
        } else {
            tracing::warn!("self-protection: failed to disable core dumps");
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn harden_process() {}

// ── Phase 2: Landlock filesystem sandbox ─────────────────────────────────────

/// Apply an irrevocable Landlock filesystem sandbox.
///
/// * Read-only access is granted to `/proc`, `/sys`, `/etc`, `/dev/urandom`
///   and any extra paths (e.g. FIM-watched files).
/// * Read-write access is granted only to `write_paths` (e.g. the event-buffer
///   directory).
/// * Every other filesystem operation is **denied**.
///
/// Called after all file handles, sinks, and inotify watches are set up — new
/// `open()` calls are subject to the sandbox, but already-open descriptors
/// (stdout, sockets, inotify fds) continue to function.
///
/// On kernels < 5.13 or builds without the `landlock` feature this is a no-op.
#[cfg(all(target_os = "linux", feature = "landlock"))]
pub fn sandbox_filesystem(extra_read_paths: &[String], write_paths: &[String]) {
    use landlock::{
        path_beneath_rules, Access, AccessFs, Ruleset, RulesetAttr,
        RulesetCreatedAttr, RulesetStatus, ABI,
    };

    // Request the newest ABI; BestEffort (default) transparently falls back
    // to whatever the running kernel supports.
    let abi = ABI::V5;

    // ── System paths required for monitoring ─────────────────────────────
    let mut read_paths: Vec<&str> = vec![
        "/proc",        // process info, /proc/net/tcp, tamper signals
        "/sys",         // sysinfo hardware/network counters
        "/etc",         // baseline checks (shadow, passwd, sshd_config …)
        "/dev/urandom", // entropy for TLS handshakes
    ];
    let extra_refs: Vec<&str> = extra_read_paths.iter().map(|s| s.as_str()).collect();
    read_paths.extend(&extra_refs);

    // Step 1 — declare handled access types (everything not in a rule is denied)
    let ruleset = match Ruleset::default().handle_access(AccessFs::from_all(abi)) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("landlock: cannot configure access handling: {e}");
            return;
        }
    };

    let created = match ruleset.create() {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                "landlock: cannot create ruleset (kernel < 5.13 or Landlock disabled): {e}"
            );
            return;
        }
    };

    // Step 2 — read-only rules for monitoring paths
    let created = match created.add_rules(path_beneath_rules(
        read_paths,
        AccessFs::from_read(abi),
    )) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("landlock: failed adding read rules: {e}");
            return;
        }
    };

    // Step 3 — read-write rules for output paths (e.g. disk-backed buffer)
    let created = if write_paths.is_empty() {
        created
    } else {
        let wp_refs: Vec<&str> = write_paths.iter().map(|s| s.as_str()).collect();
        match created.add_rules(path_beneath_rules(wp_refs, AccessFs::from_all(abi))) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("landlock: failed adding write rules: {e}");
                return;
            }
        }
    };

    // Step 4 — irrevocably apply the sandbox to this process
    match created.restrict_self() {
        Ok(status) => match status.ruleset {
            RulesetStatus::FullyEnforced => {
                tracing::info!("landlock: filesystem sandbox fully enforced");
            }
            RulesetStatus::PartiallyEnforced => {
                tracing::info!(
                    "landlock: filesystem sandbox partially enforced (kernel ABI < V5)"
                );
            }
            RulesetStatus::NotEnforced => {
                tracing::warn!(
                    "landlock: sandbox NOT enforced (kernel does not support Landlock)"
                );
            }
        },
        Err(e) => {
            tracing::warn!("landlock: failed to apply sandbox: {e}");
        }
    }
}

#[cfg(not(all(target_os = "linux", feature = "landlock")))]
pub fn sandbox_filesystem(_extra_read_paths: &[String], _write_paths: &[String]) {
    tracing::debug!("landlock sandbox: not available on this platform/build");
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harden_process_does_not_panic() {
        harden_process();
    }

    #[test]
    fn sandbox_with_empty_paths_does_not_panic() {
        sandbox_filesystem(&[], &[]);
    }

    #[test]
    fn sandbox_with_nonexistent_paths_does_not_panic() {
        sandbox_filesystem(
            &["/nonexistent/path/12345".into()],
            &["/also/nonexistent/67890".into()],
        );
    }
}
