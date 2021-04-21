use std::cmp;
use std::collections::{HashMap, VecDeque};
use std::collections::btree_map::{BTreeMap, Entry};
use std::fmt;
use std::ops::{Add, AddAssign, Sub, RangeBounds, Bound};
use std::time::Instant;
use crate::bytes::Bytes;
use crate::packet::Packet;


#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash, Default)]
struct Seq(u32);

impl Add<usize> for Seq {
    type Output = Seq;
    fn add(self, other: usize) -> Seq {
        Seq(self.0 + other as u32)
    }
}

impl AddAssign<usize> for Seq {
    fn add_assign(&mut self, other: usize) {
        *self = *self + other;
    }
}

impl Sub<Seq> for Seq {
    type Output = usize;
    fn sub(self, other: Seq) -> usize {
        (self.0 - other.0) as usize
    }
}

impl Sub<usize> for Seq {
    type Output = Seq;
    fn sub(self, other: usize) -> Seq {
        Seq(self.0 + other as u32)
    }
}

impl fmt::Display for Seq {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        <u32 as fmt::Display>::fmt(&self.0, fmt)
    }
}


/// A single direction of a TFH lobby server stream.  It consumes `Packet`s and from time to time
/// emits a `Message`.
pub struct TfhStream {
    start: Seq,
    buf: VecDeque<u8>,
    /// For each packet that has been loaded into `buf`, this maps the starting sequence number of
    /// the packet to the length and the acknowledgement sequence number.  Note the latter is a
    /// sequence number of the opposite stream, not this one.
    chunks: BTreeMap<Seq, (u32, Seq)>,
    /// Are we in sync with the stream?  If `false`, `next_message` will try some guesswork to find
    /// the start of the next message.
    sync: bool,
}

impl TfhStream {
    pub fn new() -> TfhStream {
        TfhStream {
            start: Seq(!0),
            buf: VecDeque::with_capacity(4096),
            chunks: BTreeMap::new(),
            sync: false,
        }
    }

    pub fn handle_packet(&mut self, p: &Packet) {
        if !p.is_tfh_stream() {
            return;
        }

        let tfh = p.tfh_stream();
        let data = p.tfh_stream_payload();

        let start = Seq(tfh.my_seq());
        if !self.sync && self.buf.len() == 0 {
            // Let the first packet we see set our current position in the stream.
            self.start = start;
        }
        let end = start + data.len();
        if end < self.start {
            return;
        }

        let (copy_data, offset) = if start < self.start {
            let adj = self.start - start;
            (&data[adj..], 0)
        } else {
            (data, start - self.start)
        };
        copy_slice_into_vec_deque(&mut self.buf, copy_data, offset);

        if self.start == Seq(0) {
            // We're observing the start of the entire stream.
            self.sync = true;
        }

        let ack_seq = Seq(tfh.your_seq());
        match self.chunks.entry(start) {
            Entry::Vacant(e) => {
                e.insert((data.len() as u32, ack_seq));
            },
            Entry::Occupied(e) => {
                let &mut (ref mut len, ref mut ack) = e.into_mut();
                *len = cmp::max(*len, data.len() as u32);
                *ack = cmp::max(*ack, ack_seq);
            },
        }
    }

    fn count_avail(&self) -> usize {
        let mut end = self.start;
        for (&chunk_start, &(chunk_len, _)) in &self.chunks {
            if chunk_start > end {
                break;
            }
            end = cmp::max(end, chunk_start + chunk_len as usize);
        }
        end - self.start
    }

    pub fn next_message(&mut self) -> Option<Message> {
        let avail = self.count_avail();

        // Special case: each side sends one byte before sending actual messages.  We report that
        // byte as a special message.
        if self.start == Seq(0) && avail >= 1 {
            self.start += 1;
            let body = vec![self.buf[0]];
            self.buf.drain(..1);
            return Some(Message {
                header: MessageHeader {
                    major: 0,
                    minor: 0,
                    dir: 0xff,
                    ack: 0,
                    len: 1,
                },
                body: body.into_boxed_slice(),
            });
        }

        if avail < 4 {
            return None;
        }

        // Get total message len, and check that we have enough data to read the whole message.
        let len = {
            let (a, b) = self.buf.as_slices();
            if a.len() >= 4 {
                a.u32_be(0)
            } else {
                let mut buf = [0; 4];
                buf[..a.len()].copy_from_slice(a);
                buf[a.len()..].copy_from_slice(&b[..4 - a.len()]);
                buf.u32_be(0)
            }
        };
        let len = len as usize;

        if avail < 4 + len {
            return None;
        }

        let end = self.start + 4 + len;

        // Parse the header to get the major/minor opcode.
        let mut raw_header = [0; 10];
        let raw_header_len = cmp::min(raw_header.len(), len);
        copy_vec_deque_into_slice(&mut raw_header[..raw_header_len], &self.buf, 4);

        let major = raw_header.u32_be(2);
        let minor = if major == 0x20 { raw_header.u32_le(6) } else { 0 };
        if major > u8::MAX as u32 {
            eprintln!("warning: major opcode out of range: {:x}", major);
        }
        if minor > u8::MAX as u32 {
            eprintln!("warning: major opcode out of range: {:x}", minor);
        }

        // Extract the message body.
        let header_len = 10 + if major == 0x20 { 4 } else { 0 };
        let body_len = 4 + len - header_len;
        let mut body = vec![0; body_len];
        copy_vec_deque_into_slice(&mut body, &self.buf, header_len);

        // Consume some `chunks` and compute the ack sequence number.
        let mut ack = Seq(0);
        while let Some(entry) = self.chunks.first_entry() {
            let &chunk_start = entry.key();
            if chunk_start >= end {
                break;
            }
            let &(chunk_len, chunk_ack) = entry.get();
            ack = cmp::max(ack, chunk_ack);
            if chunk_start + chunk_len as usize <= end {
                entry.remove();
            } else {
                break;
            }
        }

        self.buf.drain(.. end - self.start);
        self.start = end;

        Some(Message {
            header: MessageHeader {
                major: major as u8,
                minor: minor as u8,
                dir: 0xff,
                ack: ack.0,
                len: body_len as u32,
            },
            body: body.into_boxed_slice(),
        })
    }
}

#[repr(C)]
pub struct MessageHeader {
    pub major: u8,
    pub minor: u8,
    pub dir: u8,
    pub ack: u32,
    pub len: u32,
}

pub struct Message {
    pub header: MessageHeader,
    pub body: Box<[u8]>,
}

impl MessageHeader {
    pub fn as_bytes(&self) -> [u8; 12] {
        let mut buf = [0; 12];
        buf.put_u8_be(0, self.major);
        buf.put_u8_be(1, self.minor);
        buf.put_u8_be(2, self.dir);
        buf.put_u32_be(4, self.ack);
        buf.put_u32_be(8, self.len);
        buf
    }
}


#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum ConnTuple {
    Ipv4(u32, u16, u32, u16),
    //Ipv6([u8; 16], u16, [u8; 16], u16),
}

impl ConnTuple {
    pub fn from_udp_packet(p: &Packet, flip: bool) -> ConnTuple {
        if p.is_ipv4() {
            let hdr = p.ipv4();
            let addr1 = hdr.source_ip();
            let addr2 = hdr.dest_ip();
            let hdr = p.udp();
            let port1 = hdr.source_port();
            let port2 = hdr.dest_port();
            if !flip {
                ConnTuple::Ipv4(addr1, port1, addr2, port2)
            } else {
                ConnTuple::Ipv4(addr2, port2, addr1, port1)
            }
        } else if p.is_ipv6() {
            unimplemented!("ConnTuple ipv6")
        } else {
            panic!("packet has no ConnTuple")
        }
    }
}

pub trait StreamHandler {
    fn on_message(&mut self, ct: ConnTuple, msg: Message) {}
    fn on_timeout(&mut self, ct: ConnTuple) {}
}

pub struct TfhStreamConns<H> {
    map: HashMap<ConnTuple, StreamConn>,
    handler: H,
}

const CONN_TIMEOUT: u64 = 60;

impl<H: StreamHandler> TfhStreamConns<H> {
    pub fn new(handler: H) -> TfhStreamConns<H> {
        TfhStreamConns {
            map: HashMap::new(),
            handler,
        }
    }

    pub fn handle(&mut self, p: &Packet, flip: bool) {
        if !p.is_tfh_stream() {
            return;
        }
        let ct = ConnTuple::from_udp_packet(&p, flip);
        let sc = self.map.entry(ct).or_insert_with(StreamConn::new);

        sc.last_packet = Instant::now();

        let stream = if !flip { &mut sc.ab } else { &mut sc.ba };
        stream.handle_packet(p);

        while let Some(mut msg) = sc.ab.next_message() {
            msg.header.dir = 0;
            self.handler.on_message(ct, msg);
        }
        while let Some(mut msg) = sc.ba.next_message() {
            msg.header.dir = 1;
            self.handler.on_message(ct, msg);
        }
    }

    pub fn check_timeout(&mut self) {
        let mut remove = Vec::new();
        for (k, v) in &mut self.map {
            if v.last_packet.elapsed().as_secs() as u64 >= CONN_TIMEOUT {
                self.handler.on_timeout(*k);
                remove.push(*k);
            }
        }

        for k in remove {
            self.map.remove(&k);
        }
    }
}

struct StreamConn {
    ab: TfhStream,
    ba: TfhStream,
    last_packet: Instant,
}

impl StreamConn {
    pub fn new() -> StreamConn {
        StreamConn {
            ab: TfhStream::new(),
            ba: TfhStream::new(),
            last_packet: Instant::now(),
        }
    }
}


fn vec_deque_range_slices<T>(v: &VecDeque<T>, r: impl RangeBounds<usize>) -> (&[T], &[T]) {
    let (mut a, mut b) = v.as_slices();

    match r.end_bound() {
        Bound::Included(&i) => {
            if i < a.len() {
                a = &a[..=i];
                b = &[];
            } else {
                b = &b[..= i - a.len()];
            }
        },
        Bound::Excluded(&i) => {
            if i <= a.len() {
                a = &a[..i];
                b = &[];
            } else {
                b = &b[.. i - a.len()];
            }
        },
        Bound::Unbounded => {},
    }

    match r.start_bound() {
        Bound::Included(&i) => {
            if i < a.len() {
                a = &a[i..];
            } else {
                b = &b[i - a.len() ..];
                a = &[];
            }
        },
        Bound::Excluded(&i) => {
            if i < a.len() {
                a = &a[i + 1 ..];
            } else {
                b = &b[i + 1 ..];
                a = &[];
            }
        },
        Bound::Unbounded => {},
    }

    (a, b)
}

fn vec_deque_range_slices_mut<T>(
    v: &mut VecDeque<T>,
    r: impl RangeBounds<usize>,
) -> (&mut [T], &mut [T]) {
    let (mut a, mut b) = v.as_mut_slices();

    match r.end_bound() {
        Bound::Included(&i) => {
            if i < a.len() {
                a = &mut a[..=i];
                b = &mut [];
            } else {
                b = &mut b[..= i - a.len()];
            }
        },
        Bound::Excluded(&i) => {
            if i <= a.len() {
                a = &mut a[..i];
                b = &mut [];
            } else {
                b = &mut b[.. i - a.len()];
            }
        },
        Bound::Unbounded => {},
    }

    match r.start_bound() {
        Bound::Included(&i) => {
            if i < a.len() {
                a = &mut a[i..];
            } else {
                b = &mut b[i - a.len() ..];
                a = &mut [];
            }
        },
        Bound::Excluded(&i) => {
            if i < a.len() {
                a = &mut a[i + 1 ..];
            } else {
                b = &mut b[i + 1 ..];
                a = &mut [];
            }
        },
        Bound::Unbounded => {},
    }

    (a, b)
}

fn copy_slice_into_vec_deque<T: Copy + Default>(
    dest: &mut VecDeque<T>,
    src: &[T],
    offset: usize,
) {
    if dest.len() <= offset {
        dest.resize(offset, T::default());
        dest.extend(src);
        return;
    }

    let end = offset + src.len();
    let dest_end = cmp::min(dest.len(), end);
    let (a, b) = vec_deque_range_slices_mut(dest, offset .. dest_end);

    let (xy, z) = src.split_at(dest_end - offset);
    let (x, y) = xy.split_at(a.len());
    a.copy_from_slice(x);
    b.copy_from_slice(y);
    dest.extend(z);
}

fn copy_vec_deque_into_slice<T: Copy + Default>(
    dest: &mut [T],
    src: &VecDeque<T>,
    offset: usize,
) {
    let (a, b) = vec_deque_range_slices(src, offset .. offset + dest.len());
    let (x, y) = dest.split_at_mut(a.len());
    x.copy_from_slice(a);
    y.copy_from_slice(b);
}
