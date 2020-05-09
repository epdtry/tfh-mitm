use std::convert::TryInto;
use std::fmt;
use std::mem::{self, MaybeUninit};
use std::ops::{Deref, DerefMut};
use std::slice;
use crate::bytes::Bytes;


/// Capacity in bytes of a Packet's data buffer.  The MTU of the tun device must not exceed this
/// value; otherwise, data will be silently dropped.
pub const PACKET_CAP: usize = 1500;

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

macro_rules! define_header_accessors {
    ($Header:ty,
            $header:ident, $header_mut:ident,
            $header_payload:ident, $header_payload_mut:ident,
            $header_start:ident, $header_len:ident, $header_end:ident) => {
        // $header_start and $header_len should already be defined.  The rest will be provided.
        pub fn $header(&self) -> &$Header {
            let range = self.$header_start() .. self.$header_end();
            <$Header>::new(&self[range])
        }

        pub fn $header_mut(&mut self) -> &mut $Header {
            let range = self.$header_start() .. self.$header_end();
            <$Header>::new_mut(&mut self[range])
        }

        pub fn $header_payload(&self) -> &[u8] {
            let range = self.$header_end() ..;
            &self[range]
        }

        pub fn $header_payload_mut(&mut self) -> &mut [u8] {
            let range = self.$header_end() ..;
            &mut self[range]
        }

        pub fn $header_end(&self) -> usize {
            self.$header_start() + self.$header_len()
        }
    };
}

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


    pub fn is_ipv4(&self) -> bool {
        Ipv4Header::new(&self).version() == 4
    }

    pub fn ipv4_start(&self) -> usize {
        0
    }

    pub fn ipv4_len(&self) -> usize {
        Ipv4Header::new(&self[self.ipv4_start() ..]).ihl() as usize * 4
    }

    define_header_accessors!(
        Ipv4Header,
        ipv4, ipv4_mut, ipv4_payload, ipv4_payload_mut,
        ipv4_start, ipv4_len, ipv4_end
    );


    pub fn is_ipv6(&self) -> bool {
        Ipv4Header::new(&self).version() == 6
    }


    pub fn udp_start(&self) -> usize {
        if self.is_ipv4() {
            self.ipv4_end()
        } else if self.is_ipv6() {
            unimplemented!("udp6")
        } else {
            panic!("don't know how to find UDP header in non-IP packet")
        }
    }

    pub fn udp_len(&self) -> usize {
        8
    }

    define_header_accessors!(
        UdpHeader,
        udp, udp_mut, udp_payload, udp_payload_mut,
        udp_start, udp_len, udp_end
    );
}

impl Deref for Packet {
    type Target = [u8];
    fn deref(&self) -> &[u8] { self.as_slice() }
}

impl DerefMut for Packet {
    fn deref_mut(&mut self) -> &mut [u8] { self.as_mut_slice() }
}


macro_rules! define_header {
    ($Header:ident) => {
        #[derive(Debug)]
        #[repr(transparent)]
        pub struct $Header([u8]);

        impl $Header {
            pub fn new<'a>(x: &'a [u8]) -> &'a $Header {
                unsafe { mem::transmute(x) }
            }

            pub fn new_mut<'a>(x: &'a mut [u8]) -> &'a mut $Header {
                unsafe { mem::transmute(x) }
            }
        }

        impl Deref for $Header {
            type Target = [u8];
            fn deref(&self) -> &[u8] { &self.0 }
        }

        impl DerefMut for $Header {
            fn deref_mut(&mut self) -> &mut [u8] { &mut self.0 }
        }
    };
}


define_header!(Ipv4Header);

impl Ipv4Header {
    pub fn version(&self) -> u8 { self.0.u8_be(0) >> 4 }
    pub fn ihl(&self) -> u8 { self.0.u8_be(0) & 0x0f }
    pub fn total_len(&self) -> u16 { self.0.u16_be(2) }
    pub fn ident(&self) -> u16 { self.0.u16_be(4) }
    pub fn flags(&self) -> u8 { self.0.u8_be(6) >> 5 }
    pub fn offset(&self) -> u16 { self.0.u16_be(6) & 0x1fff }
    pub fn protocol(&self) -> u8 { self.0.u8_be(9) }
    pub fn source_ip(&self) -> u32 { self.0.u32_be(12) }
    pub fn dest_ip(&self) -> u32 { self.0.u32_be(16) }

    pub fn is_udp(&self) -> bool {
        self.protocol() == 17
    }
}

impl fmt::Display for Ipv4Header {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(
           fmt,
           "I {version:x} {ihl:x} {total_len:04x} {ident:04x} {flags:x} {offset:04x} \
               {protocol:02x} {source_ip:08x} {dest_ip:08x}",
           version = self.version(),
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

impl UdpHeader {
    pub fn source_port(&self) -> u16 { self.0.u16_be(0) }
    pub fn dest_port(&self) -> u16 { self.0.u16_be(2) }
    pub fn len(&self) -> u16 { self.0.u16_be(4) }
}

impl fmt::Display for UdpHeader {
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
        write!(fmt, "Pkt")?;
        if self.is_ipv4() {
            write!(fmt, " {}", self.ipv4())?;
            if self.ipv4().is_udp() {
                write!(fmt, "; {}", self.udp())?;
            }
        }
        if self.is_ipv6() {
            write!(fmt, " I 6")?;
        }
        Ok(())
    }
}
