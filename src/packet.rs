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
    pub fn zeroed(len: usize) -> Packet {
        let mut p = Self::default();
        assert!(len <= PACKET_CAP);
        unsafe {
            for i in 0 .. len {
                *p.as_mut_ptr().add(i) = 0;
            }
            p.set_len(len);
        }
        p
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub unsafe fn set_len(&mut self, len: usize) {
        self.0.len = len;
    }

    pub fn push(&mut self, b: u8) {
        unsafe {
            let len = self.len();
            assert!(len < PACKET_CAP);
            *self.0.as_mut_ptr().add(len) = b;
            self.set_len(len + 1);
        }
    }

    pub fn extend<I: IntoIterator<Item = u8>>(&mut self, it: I) {
        for b in it {
            self.push(b);
        }
    }

    pub fn extend_from_slice(&mut self, bs: &[u8]) {
        for &b in bs {
            self.push(b);
        }
    }

    pub fn truncate(&mut self, len: usize) {
        assert!(len <= self.len());
        unsafe { self.set_len(len) };
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

    pub fn compute_ipv4_checksum(&self) -> u16 {
        let mut acc = 0;

        let header = self.ipv4();

        for i in (0 .. header.len()).step_by(2) {
            if i == 10 {
                // The header field itself is treated as zero.
                continue;
            }

            acc = ones_complement_add(acc, header.u16_be(i));
        }

        !acc
    }


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


    pub fn is_udp(&self) -> bool {
        (self.is_ipv4() && self.ipv4().is_udp()) ||
        (self.is_ipv6() && false)   // TODO ipv6
    }

    pub fn compute_udp_checksum(&self, data: &[u8]) -> u16 {
        let mut acc = 0;

        if self.is_ipv4() {
            let mut pseudo_header = [0; 20];
            pseudo_header.put_u32_be(0, self.ipv4().source_ip());
            pseudo_header.put_u32_be(4, self.ipv4().dest_ip());
            // 8: 0
            pseudo_header.put_u8_be(9, self.ipv4().protocol());
            // "UDP length" is the length of the data plus the 8-byte UDP header.
            pseudo_header.put_u16_be(10, (data.len() + 8) as u16);
            pseudo_header.put_u16_be(12, self.udp().source_port());
            pseudo_header.put_u16_be(14, self.udp().dest_port());
            pseudo_header.put_u16_be(16, self.udp().len());
            // 18-19: 0
            for i in (0 .. pseudo_header.len()).step_by(2) {
                acc = ones_complement_add(acc, pseudo_header.u16_be(i));
            }
        } else if self.is_ipv6() {
            unimplemented!("udp checksum of ipv6 packets");
        } else {
            panic!("don't know how to checksum non-UDP/IP packets");
        }

        for i in (0 .. data.len()).step_by(2) {
            if i + 1 < data.len() {
                acc = ones_complement_add(acc, data.u16_be(i));
            } else {
                // If data.len() is odd, there will be a lone byte at the end.
                acc = ones_complement_add(acc, (data.u8_be(i) as u16) << 8);
            }
        }

        if acc == 0xffff {
            0xffff
        } else {
            !acc
        }
    }
}

impl Deref for Packet {
    type Target = [u8];
    fn deref(&self) -> &[u8] { self.as_slice() }
}

impl DerefMut for Packet {
    fn deref_mut(&mut self) -> &mut [u8] { self.as_mut_slice() }
}

fn ones_complement_add(x: u16, y: u16) -> u16 {
    let (sum, over) = x.overflowing_add(y);
    sum + over as u16
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
    pub fn checksum(&self) -> u16 { self.0.u16_be(10) }
    pub fn source_ip(&self) -> u32 { self.0.u32_be(12) }
    pub fn dest_ip(&self) -> u32 { self.0.u32_be(16) }

    pub fn set_total_len(&mut self, x: u16) { self.0.put_u16_be(2, x) }
    pub fn set_checksum(&mut self, x: u16) { self.0.put_u16_be(10, x) }

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
    pub fn checksum(&self) -> u16 { self.0.u16_be(6) }

    pub fn set_len(&mut self, x: u16) { self.0.put_u16_be(4, x) }
    pub fn set_checksum(&mut self, x: u16) { self.0.put_u16_be(6, x) }
}

impl fmt::Display for UdpHeader {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(
           fmt,
           "U {source_port:04x} {dest_port:04x} {len:04x} {checksum:04x}",
           source_port = self.source_port(),
           dest_port = self.dest_port(),
           len = self.len(),
           checksum = self.checksum(),
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
