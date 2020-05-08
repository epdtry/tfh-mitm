use std::mem::MaybeUninit;
use std::slice;

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
}

