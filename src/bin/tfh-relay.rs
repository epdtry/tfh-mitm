use std;
use std::os::unix::io::{RawFd, AsRawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use libc;
use nix::errno::Errno;
use nix::sys::socket::{ControlMessageOwned, MsgFlags};
use nix::sys::uio::IoVec;
use tfh_mitm::Error;
use tfh_mitm::packet::{Packet, PACKET_CAP};
use tfh_mitm::process::{self, Input, Output};
use tfh_mitm::tuntap;


unsafe fn read_raw(fd: RawFd, dest: *mut u8, cap: usize) -> nix::Result<usize> {
    let res = libc::read(fd, dest as *mut libc::c_void, cap);
    Errno::result(res).map(|x| x as usize)
}

fn read_packet(fd: RawFd) -> Result<Packet, Error> {
    let mut p = Packet::default();
    unsafe {
        let len = read_raw(fd, p.as_mut_ptr(), PACKET_CAP)?;
        p.set_len(len);
    }
    Ok(p)
}

fn write_packet(fd: RawFd, p: Packet) -> Result<(), Error> {
    let len = nix::unistd::write(fd, p.as_slice())?;
    assert!(len == p.len(), "failed to write entire packet: {} < {}", len, p.len());
    Ok(())
}


fn spawn_reader(
    fd: RawFd,
    mut handler: impl FnMut(Result<Packet, Error>) + Send + 'static,
) -> JoinHandle<()> {
    thread::spawn(move || {
        loop {
            let rp = read_packet(fd);
            let ok = rp.is_ok();
            handler(rp);
            if !ok {
                break;
            }
        }
    })
}

fn get_tun_from_server<P: AsRef<Path>>(path: P) -> Result<RawFd, Error> {
    let socket = UnixStream::connect(path)?;

    let mut data_buf = [0];
    let mut cmsg_buf = vec![0; 256];
    let recv_msg = nix::sys::socket::recvmsg(
        socket.as_raw_fd(),
        &[IoVec::from_mut_slice(&mut data_buf)],
        Some(&mut cmsg_buf),
        MsgFlags::empty(),
    )?;
    assert!(recv_msg.bytes == 1, "recvmsg didn't receive data: {} != 1", recv_msg.bytes);
    for cmsg in recv_msg.cmsgs() {
        match cmsg {
            ControlMessageOwned::ScmRights(fds) => {
                assert!(fds.len() == 1, "expected exactly 1 fd, but got {}", fds.len());
                return Ok(fds[0]);
            },
            _ => Err("unexpected control message type")?,
        }
    }
    return Err("didn't receive a file descriptor".into());
}

fn open_or_get_tun(name: &str) -> Result<RawFd, Error> {
    if Path::new(name).exists() {
        eprintln!("receiving tun fd from socket {:?}", name);
        get_tun_from_server(name)
    } else {
        eprintln!("creating tun device {:?}", name);
        tuntap::open_tun(name)
    }
}

fn real_main() -> Result<(), Error> {
    let args = std::env::args().collect::<Vec<_>>();
    assert!(args.len() == 3, "usage: {} outside inside", args[0]);

    let fd_a = open_or_get_tun(&args[1])?;
    let fd_b = open_or_get_tun(&args[2])?;

    println!("got tun devices {}, {}", fd_a, fd_b);

    let (inp_send, out_recv, _) = process::start_processing_thread();
    let inp_send_a = inp_send.clone();
    let inp_send_b = inp_send;

    spawn_reader(fd_a, move |r| {
        match r {
            Ok(p) => { inp_send_a.send(Input::FromA(p)).unwrap(); },
            Err(e) => { eprintln!("error reading from side A: {}", e); },
        }
    });

    spawn_reader(fd_b, move |r| {
        match r {
            Ok(p) => { inp_send_b.send(Input::FromB(p)).unwrap(); },
            Err(e) => { eprintln!("error reading from side B: {}", e); },
        }
    });

    for out in out_recv.iter() {
        match out {
            Output::ToA(p) => write_packet(fd_a, p)?,
            Output::ToB(p) => write_packet(fd_b, p)?,
        }
    }
    Ok(())
}

fn main() {
    match real_main() {
        Ok(()) => {},
        Err(e) => {
            println!("error: {}", e);
            std::process::exit(1);
        },
    }
}
