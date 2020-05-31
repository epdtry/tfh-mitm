use std::convert::TryInto;
use std::fmt::Write;
use std::str;
use std::sync::mpsc::{self, Sender, Receiver};
use std::thread::{self, JoinHandle};
use crate::packet::Packet;


pub enum Input {
    FromA(Packet),
    FromB(Packet),
}

pub enum Output {
    ToA(Packet),
    ToB(Packet),
}

pub fn start_processing_thread() -> (Sender<Input>, Receiver<Output>, JoinHandle<()>) {
    let (inp_send, inp_recv) = mpsc::channel();
    let (out_send, out_recv) = mpsc::channel();
    let join = thread::spawn(move || process(inp_recv, out_send));
    (inp_send, out_recv, join)
}

pub fn process(input: Receiver<Input>, output: Sender<Output>) {
    for inp in input.iter() {
        match inp {
            Input::FromA(p) => {
                //println!("A -> B: {} bytes: {}", p.len(), p);
                output.send(Output::ToB(p)).unwrap();
            },
            Input::FromB(mut p) => {
                //println!("B -> A: {} bytes: {}", p.len(), p);

                if p.is_udp() && p.udp().source_port() == 27016 {
                    println!("status: {}", dump_mixed(p.udp_payload()));
                    edit_server_status(&mut p)
                        .unwrap_or_else(|e| eprintln!("status: {}", e));
                    println!("edited: {}", dump_mixed(p.udp_payload()));
                    println!("B -> A (edited): {} bytes: {}", p.len(), p);
                }

                output.send(Output::ToA(p)).unwrap();
            },
        }
    }
}

macro_rules! require {
    ($cond:expr) => {
        if !$cond { return Err("malformed packet"); }
    };
}

fn edit_server_status(p: &mut Packet) -> Result<(), &'static str> {
    require!(p.is_udp());


    // Set current player count to zero

    // Protocol docs: https://developer.valvesoftware.com/wiki/Server_queries
    //
    // Starting at offset 6, there are four null-terminated strings.  The current and max player
    // count fields are after those.
    let b = p.udp_payload_mut();
    let mut i = 6;
    let mut str_start = [0; 4];
    for j in 0..4 {
        str_start[j] = i;
        while i < b.len() && b[i] != 0 {
            i += 1;
        }
        i += 1;
    }
    require!(i + 3 < b.len());
    println!("offset {}, players: {} / {}", i, b[i + 2], b[i + 3]);
    b[i + 2] = 0;


    // Change server name.  This requires resizing the packet.
    let name_start = p.udp_end() + str_start[0];
    let name_end = p.udp_end() + str_start[1];

    let mut q = Packet::zeroed(0);
    q.extend(p[..name_start].iter().cloned());
    q.extend(b"Leaf (shitter)\0".iter().cloned());
    q.extend(p[name_end..].iter().cloned());
    *p = q;


    // Fix len and checksum

    let new_total_len = p.len().try_into().unwrap();
    p.ipv4_mut().set_total_len(new_total_len);
    let new_udp_len = (p.len() - p.udp_start()).try_into().unwrap();
    p.udp_mut().set_len(new_udp_len);

    let ipv4_checksum = p.compute_ipv4_checksum();
    p.ipv4_mut().set_checksum(ipv4_checksum);

    // Checksums are optional in UDP/IPv4, so we could set it to zero (unused) instead.  But that
    // has the inexplicable side effect of making player count appear to be zero, regardless of the
    // value in the packet, and might cause other weird effects too.
    let udp_checksum = p.compute_udp_checksum(p.udp_payload());
    p.udp_mut().set_checksum(udp_checksum);
    Ok(())
}

fn dump_hex(b: &[u8]) -> String {
    if b.len() == 0 {
        return String::new();
    }

    let mut s = String::with_capacity(b.len() * 3 - 1);
    for (i, &x) in b.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        write!(s, "{:02x}", x).unwrap();
    }
    s
}

fn dump_mixed(b: &[u8]) -> String {
    if b.len() == 0 {
        return String::new();
    }

    let mut out = String::with_capacity(b.len() * 3 - 1);
    let mut i = 0;
    while i < b.len() {
        if i > 0 {
            out.push(' ');
        }
        let x = b[i];
        if is_printable_ascii(x) {
            let j = b[i..].iter().position(|&x| !is_printable_ascii(x))
                .map_or(b.len(), |off| i + off);
            assert!(j > i);
            if j >= i + 2 {
                let s = str::from_utf8(&b[i..j]).unwrap();
                write!(out, "{:?}", s).unwrap();
            } else {
                write!(out, "{:?}", x as char).unwrap();
            }
            i = j;
        } else {
            write!(out, "{:02x}", x).unwrap();
            i += 1;
        }
    }
    out
}

fn is_printable_ascii(x: u8) -> bool {
    x >= 0x20 && x < 0x7f
}
