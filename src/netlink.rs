#[cfg(target_os = "linux")]
pub mod proc_connector {
    use std::io;
    use std::mem;
    use std::os::unix::io::AsRawFd;
    use crate::events::ProcessEvent;

    // Define Netlink Connector structs
    /* 
       To keep this succinct but accurate:
       This would bind to NETLINK_CONNECTOR and listen to PROC_CN_MCAST_LISTEN.
    */
}
