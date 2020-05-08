use std::io;
use std::mem::MaybeUninit;
use std::process;
use std::os::unix::io::RawFd;
use nix;
use nix::fcntl::OFlag;
use nix::sys::stat::Mode;
use libc::{
    c_int, c_short, c_char, c_void, c_ulong, c_uint, c_ushort, c_uchar, sockaddr,
    IFNAMSIZ, IFF_TUN, IFF_NO_PI,
};
use crate::{Error, ErrorAt};


// struct ifreq is not declared in rust's libc bindings

#[repr(C)]
pub struct ifmap {
    pub mem_start: c_ulong,
    pub mem_end: c_ulong,
    pub base_addr: c_ushort,
    pub irq: c_uchar,
    pub dma: c_uchar,
    pub port: c_uchar,
}

#[repr(C)]
pub struct if_settings {
    pub type_: c_uint,
    pub size: c_uint,
    pub data: *mut c_void,
}

#[repr(C)]
pub union ifreq_ifrn {
    pub ifrn_name: [c_char; IFNAMSIZ]
}

#[repr(C)]
pub union ifreq_ifru {
    pub ifru_addr: sockaddr,
    pub ifru_dstaddr: sockaddr,
    pub ifru_broadaddr: sockaddr,
    pub ifru_netmask: sockaddr,
    pub ifru_hwaddr: sockaddr,
    pub ifru_flags: c_short,
    pub ifru_ivalue: c_int,
    pub ifru_mtu: c_int,
    pub ifru_map: ifmap,
    pub ifru_slave: [c_char; IFNAMSIZ],
    pub ifru_newname: [c_char; IFNAMSIZ],
    pub ifru_data: *mut c_void,
    pub ifru_settings: if_settings,
}

#[repr(C)]
pub struct ifreq {
    pub ifr_ifrn: ifreq_ifrn,
    pub ifr_ifru: ifreq_ifru,
}

nix::ioctl_write_ptr!(tun_set_iff, b'T', 202, c_int);


pub fn open_tun(if_name: &str) -> Result<RawFd, Error> {
    let fd = nix::fcntl::open(
        "/dev/net/tun",
        OFlag::O_RDWR,
        Mode::empty(),
    ).at("opening tun device")?;

    unsafe {
        let mut ifr = MaybeUninit::<ifreq>::zeroed();
        let ifrp = ifr.as_mut_ptr();
        (*ifrp).ifr_ifru.ifru_flags = IFF_TUN as c_short;
        for (i, &b) in if_name.as_bytes().iter().enumerate() {
            (*ifrp).ifr_ifrn.ifrn_name[i] = b as c_char;
        }
        (*ifrp).ifr_ifrn.ifrn_name[if_name.len()] = 0;
        let ifr = ifr.assume_init();

        tun_set_iff(fd, &ifr as *const _ as *const c_int).at("set tun interface name")?;
    };

    Ok(fd)
}
