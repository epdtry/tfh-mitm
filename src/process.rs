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
                println!("A -> B: {} bytes: {}", p.len(), p);
                output.send(Output::ToB(p)).unwrap();
            },
            Input::FromB(p) => {
                println!("B -> A: {} bytes: {}", p.len(), p);
                output.send(Output::ToA(p)).unwrap();
            },
        }
    }
}
