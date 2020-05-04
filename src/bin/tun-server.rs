use std::env;
use std::fs;
use std::mem::{self, MaybeUninit};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::io::{RawFd, AsRawFd};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process;
use std::slice;
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use libc;
use nix::errno::Errno;
use nix::sys::socket::{ControlMessage, MsgFlags};
use nix::sys::stat::Mode;
use nix::sys::uio::IoVec;
use tfh_mitm::Error;
use tfh_mitm::tuntap;


fn real_main() -> Result<(), Error> {
    let args = std::env::args().collect::<Vec<_>>();
    assert!(args.len() == 3, "usage: {} tunXX socket", args[0]);
    let tun_fd = tuntap::open_tun(&args[1])?;


    // `bind` will fail if the socket already exists from a previous run.
    let socket_path = Path::new(&args[2]);
    match socket_path.symlink_metadata() {
        Ok(m) => {
            // For safety, we only remove if it's really a socket.  Other files are left intact
            // (and will cause `bind` to fail later on).
            if m.file_type().is_socket() {
                fs::remove_file(socket_path)?;
            }
        },
        // Ignore errors, particularly "not found".
        Err(_) => {},
    }

    nix::sys::stat::umask(Mode::S_IRWXG | Mode::S_IRWXO);
    let listener = UnixListener::bind(&args[2])?;
    for socket in listener.incoming() {
        let socket = socket?;
        let len = nix::sys::socket::sendmsg(
            socket.as_raw_fd(),
            // TODO: Not sure this is necessary, but I seem to recall that sendmsg doesn't work if
            // the message is empty.
            &[IoVec::from_slice(&[0])],
            &[ControlMessage::ScmRights(&[tun_fd])],
            MsgFlags::empty(),
            None,
        )?;
        assert!(len == 1, "sendmsg didn't send data: {} != 1", len);
        drop(socket);
    }

    Ok(())
}

fn main() {
    match real_main() {
        Ok(()) => {},
        Err(e) => {
            println!("error: {}", e);
            process::exit(1);
        },
    }
}
