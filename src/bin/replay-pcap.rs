use std::env;
use std::fs::File;
use std::io;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::thread;
use tfh_mitm::packet::{Packet, PACKET_CAP};
use tfh_mitm::pcap::Pcap;
use tfh_mitm::process::{self, Input, Output};


fn real_main() -> Result<(), io::Error> {
    let args = std::env::args().collect::<Vec<_>>();
    assert!(args.len() == 3, "usage: {} file.pcap server_ip", args[0]);
    let mut pcap = Pcap::new(File::open(&args[1])?)?;
    let server_ip = Ipv4Addr::from_str(&args[2]).unwrap();
    let server_ip = u32::from_be_bytes(server_ip.octets());

    let (inp_send, out_recv, _) = process::start_processing_thread();

    thread::spawn(move || {
        for _ in out_recv.iter() {
            // Ignore
        }
    });

    loop {
        let p = pcap.read()?;
        if !p.is_ipv4() {
            continue;
        }

        // `A` is the outside of the sandbox and `B` is the inside.  So packets destined for the
        // server are traveling from A to B.
        let inp = if p.ipv4().dest_ip() == server_ip {
            Input::FromA(p)
        } else if p.ipv4().source_ip() == server_ip {
            Input::FromB(p)
        } else {
            continue;
        };

        inp_send.send(inp).unwrap();
    }

    Ok(())
}

fn main() {
    match real_main() {
        Ok(()) => {},
        Err(e) => {
            println!("error: {}", e);
            std::process::exit(1);
        },
    }
}
