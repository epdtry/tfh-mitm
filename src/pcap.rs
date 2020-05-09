use std::io::{self, Read};
use std::mem;
use std::slice;
use crate::packet::{Packet, PACKET_CAP};


#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[repr(C)]
struct GlobalHeader {
    magic: u32,
    v_major: u16,
    v_minor: u16,
    tz_off: u32,
    sig_figs: u32,
    snap_len: u32,
    net_type: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
#[repr(C)]
pub struct Timestamp {
    pub sec: i32,
    pub usec: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[repr(C)]
struct PacketHeader {
    time: Timestamp,
    inc_len: u32,
    orig_len: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[repr(C)]
struct EthernetHeader {
    dest_mac: [u8; 6],
    src_mac: [u8; 6],
    /// A big-endian u16.
    ethertype: [u8; 2],
}


pub struct Pcap<R> {
    r: R,
}

unsafe fn read_into<R: Read, T>(r: &mut R, t: *mut T) -> io::Result<()> {
    r.read_exact(slice::from_raw_parts_mut(t as *mut u8, mem::size_of::<T>()))
}

impl<R: Read> Pcap<R> {
    pub fn new(mut r: R) -> io::Result<Pcap<R>> {
        let mut gh = GlobalHeader::default();
        unsafe { read_into(&mut r, &mut gh)? };
        assert!(gh.magic == 0xa1b2c3d4);
        Ok(Pcap { r })
    }

    pub fn try_read(&mut self) -> io::Result<Option<Packet>> {
        let mut ph = PacketHeader::default();
        unsafe { read_into(&mut self.r, &mut ph)? };
        let mut len = ph.inc_len as usize;

        if len < mem::size_of::<EthernetHeader>() {
            self.r.read_exact(&mut vec![0; len])?;
            return Ok(None);
        }

        let mut eh = EthernetHeader::default();
        unsafe { read_into(&mut self.r, &mut eh)? };
        len -= mem::size_of::<EthernetHeader>();
        let ethertype = u16::from_be_bytes(eh.ethertype);
        // Only return IPv4 and IPv6 packets.
        if ethertype != 0x0800 && ethertype != 0x86dd {
            self.r.read_exact(&mut vec![0; len])?;
            return Ok(None);
        }

        let mut p = Packet::zeroed(len);
        self.r.read_exact(&mut p)?;
        Ok(Some(p))
    }

    pub fn read(&mut self) -> io::Result<Packet> {
        loop {
            match self.try_read()? {
                Some(x) => return Ok(x),
                None => {},
            }
        }
    }
}
