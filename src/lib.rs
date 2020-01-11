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

use std::net;

pub fn run() {
    // TODO : Load peers to communicate with
    let node_addr: net::Ipv4Addr = "217.20.130.72".parse().unwrap();
    let port = 8333;

    let stream =
        net::TcpStream::connect((node_addr, port)).expect("Couldn't connect to remote host...");

    println!("Connected to {} on port {}", node_addr, port);

    let mut node = network::Node::new(stream);
    node.connect();
}
