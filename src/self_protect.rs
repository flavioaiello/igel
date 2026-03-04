#[cfg(target_os = "linux")]
pub fn secure_igel_process() {
    use tracing::info;
    unsafe {
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) == 0 {
            info!("Self-Protection: PR_SET_DUMPABLE disabled");
        }
    }
}
#[cfg(not(target_os = "linux"))]
pub fn secure_igel_process() {}
