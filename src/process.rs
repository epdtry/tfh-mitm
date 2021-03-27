use std::cmp;
use std::collections::hash_map::{HashMap, Entry};
use std::convert::TryInto;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{self, Write as _};
use std::str;
use std::sync::mpsc::{self, Sender, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use rand::{self, Rng};
use crate::bytes::Bytes;
use crate::packet::Packet;
use crate::tfh_stream::{TfhStreamConns, ConnTuple, StreamHandler, Message};


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

#[derive(Default)]
struct StreamHandlerImpl {
    logs: HashMap<ConnTuple, File>,
    names: HashMap<ConnTuple, String>,
}

impl StreamHandlerImpl {
    fn try_log_message(&mut self, ct: ConnTuple, msg: Message) -> io::Result<()> {
        let log = match self.logs.entry(ct) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => {
                let (client_ip, client_port, server_port) = match ct {
                    ConnTuple::Ipv4(ci, cp, si, sp) => (ci, cp, sp),
                };
                let mut client_ip_bytes = [0; 4];
                client_ip_bytes.put_u32_be(0, client_ip);
                let [a, b, c, d] = client_ip_bytes;
                let name = format!("logs/{}-{}.{}.{}.{}-{}-{}.tfhlog",
                    now(), a, b, c, d, client_port, server_port);
                e.insert(File::create(name)?)
            },
        };

        log.write_all(&msg.header.as_bytes())?;
        log.write_all(&msg.body)?;
        Ok(())
    }

    fn try_update_status(&mut self) -> io::Result<()> {
        let mut f = File::create("status.txt")?;
        if self.names.len() == 0 {
            writeln!(f, "0 players connected")?;
            return Ok(());
        }
        writeln!(f, "{} player{} connected:",
            self.names.len(),
            if self.names.len() != 1 { "s" } else { "" },
        )?;
        let mut names = self.names.values().collect::<Vec<_>>();
        names.sort();
        for name in names {
            writeln!(f, "- {}", name)?;
        }
        Ok(())
    }

    fn update_status(&mut self) {
        match self.try_update_status() {
            Ok(()) => {},
            Err(e) => {
                eprintln!("error: failed to update status.txt: {}", e);
            },
        }
    }
}

impl StreamHandler for StreamHandlerImpl {
    fn on_message(&mut self, ct: ConnTuple, msg: Message) {
        if msg.header.dir == 0 && msg.header.major == 0x0a {
            if let Some(name_bytes) = msg.body.get(12 .. 12 + 64) {
                let name = String::from_utf8_lossy(name_bytes).into_owned();
                eprintln!("{:?}: logged in as {}", ct, name);
                self.names.insert(ct, name);
                self.update_status();
            }
        }

        match self.try_log_message(ct, msg) {
            Ok(()) => {},
            Err(e) => {
                eprintln!("error: failed to log message for {:?}: {}", ct, e);
            },
        }
    }

    fn on_timeout(&mut self, ct: ConnTuple) {
        eprintln!("{:?}: timed out", ct);
        self.logs.remove(&ct);
        if self.names.remove(&ct).is_some() {
            self.update_status();
        }
    }
}

pub fn process(input: Receiver<Input>, output: Sender<Output>) {
    fs::create_dir_all("logs").unwrap();

    let mut stream_conns = TfhStreamConns::new(StreamHandlerImpl::default());

    for inp in input.iter() {
        match inp {
            Input::FromA(p) => {
                stream_conns.handle(&p, false);
                output.send(Output::ToB(p)).unwrap();
            },

            Input::FromB(mut p) => {
                stream_conns.handle(&p, true);

                if p.is_udp() {
                    let port = p.udp().source_port();
                    if port >= 27010 && port <= 27030 {
                        edit_server_status(&mut p)
                            .unwrap_or_else(|e| eprintln!("status: {}", e));
                        println!("status: {}", dump_mixed(p.udp_payload()));
                    }
                }

                output.send(Output::ToA(p)).unwrap();
            },
        }
    }

    stream_conns.check_timeout();
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
    for j in 0..4 {
        while i < b.len() && b[i] != 0 {
            i += 1;
        }
        i += 1;
    }
    require!(i + 3 < b.len());
    b[i + 2] = 0;


    // Checksums are optional in UDP/IPv4, so we could set it to zero (unused) instead.  But that
    // has the inexplicable side effect of making player count appear to be zero, regardless of the
    // value in the packet, and might cause other weird effects too.
    p.update_udp_checksum();
    Ok(())
}

fn contains_drop_command(p: &Packet) -> bool {
    if !p.is_tfh_stream() {
        return false;
    }
    let payload = p.tfh_stream_payload();
    for i in 0 .. payload.len() {
        if payload[i..].starts_with(b"dropthis") {
            return true;
        }
    }
    false
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


fn now() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(dur) => dur.as_secs() as i64,
        Err(e) => -(e.duration().as_secs() as i64),
    }
}
