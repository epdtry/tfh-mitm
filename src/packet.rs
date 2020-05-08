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

    pub fn kernel(&self) -> &KernelHeader {
        let arr: &[u8; 4] = self.as_slice()[0 .. 4].try_into().unwrap();
        unsafe { mem::transmute(arr) }
    }
}


#[repr(transparent)]
pub struct KernelHeader([u8; 4]);

impl KernelHeader {
    pub fn flags(&self) -> u16 { self.0.u16_be(0) }
    pub fn proto(&self) -> u16 { self.0.u16_be(2) }

    pub fn is_ipv4(&self) -> bool {
        self.proto() == 0x0800
    }

    pub fn is_ipv6(&self) -> bool {
        self.proto() == 0x86dd
    }
}

impl Deref for KernelHeader {
    type Target = [u8; 4];
    fn deref(&self) -> &[u8; 4] { &self.0 }
}

impl fmt::Display for KernelHeader {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "K {:04x} {:04x}", self.flags(), self.proto())
    }
}
