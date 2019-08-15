extern crate hex;
extern crate rand;

mod block;
mod crypto;
mod merkle_tree;
mod message;
mod network;
mod script;
mod transaction;
mod utils;
mod variable_integer;

use crate::rand::RngCore;
use std::io::{Read, Write};
use std::net;
use std::sync::mpsc;
use std::thread;
use std::time::SystemTime;

use crate::message::MessageCommand;

pub fn run() {
    // TODO : Load peers to communicate with
    let node_addr: net::Ipv4Addr = "192.206.202.6".parse().unwrap();
    let port = 8333;

    let stream =
        net::TcpStream::connect((node_addr, port)).expect("Couldn't connect to remote host...");

    println!("Connected to {} on port {}", node_addr, port);

    let input_stream = stream.try_clone().unwrap();

    let (t_cw, r_cw) = mpsc::channel();
    let (t_rc, r_rc) = mpsc::channel();

    thread::spawn(move || reader(input_stream, t_rc));
    thread::spawn(move || writer(stream, r_cw));

    // Init connection by sending version message
    let my_addr: net::Ipv4Addr = "0.0.0.0".parse().unwrap();
    let mut data = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut data);
    let version = message::version::MessageVersion::new(
        70013,
        message::NODE_NETWORK,
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u64,
        network::NetAddrVersion::new(message::NODE_NETWORK, node_addr.to_ipv6_mapped(), port),
        network::NetAddrVersion::new(message::NODE_NETWORK, my_addr.to_ipv6_mapped(), 0),
        u64::from_le_bytes(data),
        "/yasbit:0.1.0/".to_string(),
        0,
        true,
    );
    println!("Sending version message : {:?}", version);
    let message = message::Message::new(message::MAGIC_MAIN, version);
    t_cw.send(message.bytes()).unwrap();

    // This thread is the controller
    loop {
        let message_type = r_rc.recv().unwrap();
        // Do something with the message
        handle_message(message_type, &t_cw);
    }
}

fn writer(mut stream: net::TcpStream, r_cw: mpsc::Receiver<Vec<u8>>) {
    loop {
        let bytes = r_cw.recv().unwrap();
        stream.write(&bytes).unwrap();
        stream.flush().unwrap();
    }
}

fn reader(mut stream: net::TcpStream, t_rc: mpsc::Sender<message::MessageType>) {
    let mut bytes = Vec::new();
    let mut buffer = [0 as u8; 100];
    let mut remaining_bytes = 0;
    loop {
        let received_bytes = stream.read(&mut buffer).unwrap();
        println!("{} bytes received", received_bytes);
        if received_bytes == 0 {
            println!("remote closed connection");
            break;
        }
        let mut index = 0;
        loop {
            let mut curr_mess_bytes =
                if remaining_bytes > 0 && remaining_bytes < (received_bytes - index) {
                    remaining_bytes
                } else {
                    received_bytes - index
                };

            // re-initialize remaining bytes
            remaining_bytes = 0;
            let previous_bytes = bytes.len();
            bytes.extend_from_slice(&buffer[index..(curr_mess_bytes + index)]);

            match message::parse(&bytes) {
                Ok((message_type, used_bytes)) => {
                    curr_mess_bytes = used_bytes - previous_bytes;
                    // Send the message to the controller
                    t_rc.send(message_type).unwrap();
                }
                Err(message::ParseError::Partial(needed)) => {
                    remaining_bytes = needed;
                }
                Err(err) => {
                    println!("Error {:?}! Message received: {:?}", &err, &buffer.to_vec());
                }
            }

            if remaining_bytes == 0 {
                bytes.clear();
            }

            if received_bytes - index > curr_mess_bytes {
                // process another message in the received bytes
                index += curr_mess_bytes;
            } else {
                break;
            }
        }
    }
}

fn handle_message(message_type: message::MessageType, t_cw: &mpsc::Sender<Vec<u8>>) {
    match message_type {
        message::MessageType::Alert(mess) => {
            display_message(&mess.command);
            mess.command.handle(&t_cw)
        }
        message::MessageType::Version(mess) => {
            display_message(&mess.command);
            mess.command.handle(&t_cw)
        }
        message::MessageType::Verack(mess) => {
            display_message(&mess.command);
            mess.command.handle(&t_cw)
        }
        message::MessageType::GetAddr(mess) => {
            display_message(&mess.command);
            mess.command.handle(&t_cw)
        }
        message::MessageType::Addr(mess) => {
            display_message(&mess.command);
            mess.command.handle(&t_cw)
        }
        message::MessageType::Ping(mess) => {
            display_message(&mess.command);
            mess.command.handle(&t_cw)
        }
        message::MessageType::Pong(mess) => {
            display_message(&mess.command);
            mess.command.handle(&t_cw)
        }
        message::MessageType::GetHeaders(mess) => {
            display_message(&mess.command);
            mess.command.handle(&t_cw)
        }
        message::MessageType::FeeFilter(mess) => {
            display_message(&mess.command);
            mess.command.handle(&t_cw)
        }
    };
}

pub fn display_message<T: message::MessageCommand + std::fmt::Debug>(command: &T) {
    println!(
        "Received {} message: {:?}",
        std::str::from_utf8(&command.name()).unwrap(),
        command
    );
}
