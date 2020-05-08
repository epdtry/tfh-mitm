use std::convert::TryInto;
use std::fmt;
use std::mem::{self, MaybeUninit};
use std::ops::Deref;
use std::slice;
use crate::bytes::Bytes;


/// Capacity in bytes of a Packet's data buffer, including the kernel-provided flags and protocol
/// fields.  The MTU of the TUN device, plus 4 for the kernel header, must fit within `PACKET_CAP`;
/// otherwise, data will be silently dropped.
pub const PACKET_CAP: usize = 1500 + 4;

struct PacketInner {
    data: MaybeUninit<[u8; PACKET_CAP]>,
    len: usize,
}

impl Default for PacketInner {
    fn default() -> PacketInner {
        PacketInner {
            data: MaybeUninit::uninit(),
            len: 0,
        }
    }
}

impl PacketInner {
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn as_slice<'a>(&'a self) -> &'a [u8] {
        unsafe { slice::from_raw_parts(self.data.as_ptr() as *const u8, self.len) }
    }

    pub fn as_mut_slice<'a>(&'a mut self) -> &'a mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.data.as_mut_ptr() as *mut u8, self.len) }
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.data.as_ptr() as *const u8
    }

    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.data.as_mut_ptr() as *mut u8
    }
}

#[derive(Default)]
pub struct Packet(Box<PacketInner>);

impl Packet {
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn set_len(&mut self, len: usize) {
        self.0.len = len;
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.0.as_ptr()
    }

    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.0.as_mut_ptr()
    }


    pub fn kernel_start(&self) -> usize {
        0
    }

    pub fn kernel_len(&self) -> usize {
        4
    }

    pub fn kernel_end(&self) -> usize {
        self.kernel_start() + self.kernel_len()
    }

    pub fn kernel(&self) -> KernelHeader {
        KernelHeader(&self[self.kernel_start() .. self.kernel_end()])
    }


    pub fn ipv4_start(&self) -> usize {
        self.kernel_end()
    }

    pub fn ipv4_len(&self) -> usize {
        Ipv4Header(&self[self.ipv4_start() ..]).ihl() as usize * 4
    }

    pub fn ipv4_end(&self) -> usize {
        self.ipv4_start() + self.ipv4_len()
    }

    pub fn ipv4(&self) -> Ipv4Header {
        Ipv4Header(&self[self.ipv4_start() .. self.ipv4_end()])
    }


    pub fn udp_start(&self) -> usize {
        if self.kernel().is_ipv4() {
            self.ipv4_end()
        } else if self.kernel().is_ipv6() {
            unimplemented!("udp6")
        } else {
            panic!("don't know how to find UDP header in non-IP packet")
        }
    }

    pub fn udp_len(&self) -> usize {
        8
    }

    pub fn udp_end(&self) -> usize {
        self.udp_start() + self.udp_len()
    }

    pub fn udp(&self) -> UdpHeader {
        UdpHeader(&self[self.udp_start() .. self.udp_end()])
    }
}

impl Deref for Packet {
    type Target = [u8];
    fn deref(&self) -> &[u8] { self.as_slice() }
}


macro_rules! define_header {
    ($Header:ident) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $Header<'a>(&'a [u8]);

        impl Deref for $Header<'_> {
            type Target = [u8];
            fn deref(&self) -> &[u8] { self.0 }
        }
    };
}


define_header!(KernelHeader);

impl KernelHeader<'_> {
    pub fn flags(self) -> u16 { self.0.u16_be(0) }
    pub fn proto(self) -> u16 { self.0.u16_be(2) }

    pub fn is_ipv4(self) -> bool {
        self.proto() == 0x0800
    }

    pub fn is_ipv6(self) -> bool {
        self.proto() == 0x86dd
    }
}

impl fmt::Display for KernelHeader<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "K {:04x} {:04x}", self.flags(), self.proto())
    }
}


define_header!(Ipv4Header);

impl Ipv4Header<'_> {
    pub fn ihl(self) -> u8 { self.0.u8_be(0) & 0x0f }
    pub fn total_len(self) -> u16 { self.0.u16_be(2) }
    pub fn ident(self) -> u16 { self.0.u16_be(4) }
    pub fn flags(self) -> u8 { self.0.u8_be(6) >> 5 }
    pub fn offset(self) -> u16 { self.0.u16_be(6) & 0x1fff }
    pub fn protocol(self) -> u8 { self.0.u8_be(9) }
    pub fn source_ip(self) -> u32 { self.0.u32_be(12) }
    pub fn dest_ip(self) -> u32 { self.0.u32_be(16) }

    pub fn is_udp(self) -> bool {
        self.protocol() == 17
    }
}

impl fmt::Display for Ipv4Header<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(
           fmt,
           "I {ihl:x} {total_len:04x} {ident:04x} {flags:x} {offset:04x} \
               {protocol:02x} {source_ip:08x} {dest_ip:08x}",
           ihl = self.ihl(),
           total_len = self.total_len(),
           ident = self.ident(),
           flags = self.flags(),
           offset = self.offset(),
           protocol = self.protocol(),
           source_ip = self.source_ip(),
           dest_ip = self.dest_ip(),
       )
    }
}


define_header!(UdpHeader);

impl UdpHeader<'_> {
    pub fn source_port(self) -> u16 { self.0.u16_be(0) }
    pub fn dest_port(self) -> u16 { self.0.u16_be(2) }
    pub fn len(self) -> u16 { self.0.u16_be(4) }
}

impl fmt::Display for UdpHeader<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(
           fmt,
           "U {source_port:04x} {dest_port:04x} {len:04x}",
           source_port = self.source_port(),
           dest_port = self.dest_port(),
           len = self.len(),
       )
    }
}


impl fmt::Display for Packet {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{}", self.kernel())?;
        if self.kernel().is_ipv4() {
            write!(fmt, "; {}", self.ipv4())?;
            if self.ipv4().is_udp() {
                write!(fmt, "; {}", self.udp())?;
            }
        }
        Ok(())
    }
}
