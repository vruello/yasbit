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
use std::time::SystemTime;

use crate::message::MessageCommand;
use block::Block;
use crypto::Hashable;
use transaction::Transaction;

pub fn run() {
    let node_addr: net::Ipv4Addr = "192.206.202.6".parse().unwrap();
    let my_addr: net::Ipv4Addr = "0.0.0.0".parse().unwrap();

    let mut data = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut data);
    let message_version = message::version::MessageVersion::new(
        70013,
        message::NODE_NETWORK,
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u64,
        network::NetAddrVersion::new(message::NODE_NETWORK, node_addr.to_ipv6_mapped(), 0),
        network::NetAddrVersion::new(message::NODE_NETWORK, my_addr.to_ipv6_mapped(), 0),
        u64::from_le_bytes(data),
        "/yasbit:0.1.0/".to_string(),
        0,
        true,
    );

    let message = message::Message::new(message::MAGIC_MAIN, message_version);
    let port = 8333;

    if let Ok(mut stream) = net::TcpStream::connect((node_addr, port)) {
        println!("Connected to {} on port {}", node_addr, port);
        println!(
            "Sending message {} : {:?}",
            std::str::from_utf8(&message.command.name()).unwrap(),
            message.command
        );
        stream.write(&message.bytes()).expect("write");
        stream.flush().unwrap();

        let mut bytes = Vec::new();
        let mut buffer = [0 as u8; 100];
        let mut remaining_bytes = 0;
        loop {
            println!("Waiting for bytes...");
            let received_bytes = stream.read(&mut buffer).unwrap();
            println!("{} bytes received", received_bytes);
            if received_bytes == 0 {
                println!("Remote closed connection");
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

                // Re-initialize remaining bytes
                remaining_bytes = 0;
                let previous_bytes = bytes.len();
                bytes.extend_from_slice(&buffer[index..(curr_mess_bytes + index)]);

                match message::parse(&bytes) {
                    Ok((message_type, used_bytes)) => {
                        curr_mess_bytes = used_bytes - previous_bytes;
                        handle_message(message_type)
                    }
                    Err(message::ParseError::Partial(needed)) => {
                        remaining_bytes = needed;
                    }
                    Err(err) => {
                        println!("Error {:?}. Message received: {:?}", &err, &buffer.to_vec());
                    }
                }

                if remaining_bytes == 0 {
                    bytes.clear();
                }

                if received_bytes - index > curr_mess_bytes {
                    // Process another message in the received bytes
                    index += curr_mess_bytes;
                } else {
                    break;
                }
            }
        }
    } else {
        println!("Couldn't connect to remote.");
    }
}

fn handle_message(message_type: message::MessageType) {
    match message_type {
        message::MessageType::Alert(mess) => println!(
            "Receive message {} : {:?}",
            std::str::from_utf8(&mess.command.name()).unwrap(),
            mess.command
        ),
        message::MessageType::Version(mess) => println!(
            "Receive message {} : {:?}",
            std::str::from_utf8(&mess.command.name()).unwrap(),
            mess.command
        ),
        message::MessageType::Verack(mess) => println!(
            "Receive message {} : {:?}",
            std::str::from_utf8(&mess.command.name()).unwrap(),
            mess.command
        ),
    };
}
