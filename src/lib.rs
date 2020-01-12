extern crate hex;
extern crate rand;
mod block;
mod crypto;
mod merkle_tree;
mod message;
mod network;
mod node;
mod script;
mod transaction;
mod utils;
mod variable_integer;

use std::net;
use std::sync::mpsc;
use std::thread;

pub fn run() {
    // TODO : Load peers to communicate with
    let addrs = ["5.43.228.99:8333", "5.8.18.29:8333"];
    let mut nodes = vec![];
    let (response_sender, response_receiver) = mpsc::channel();

    for addr in &addrs {
        let (command_sender, command_receiver) = mpsc::channel();
        let node_id = nodes.len();
        nodes.push(command_sender);
        let node_response_sender = response_sender.clone();
        let node_addr = addr.parse().unwrap();
        thread::spawn(move || {
            start_node(node_id, node_addr, command_receiver, node_response_sender)
        });
    }

    loop {
        let response = response_receiver.recv().unwrap();

        match response {
            node::NodeResponse::Ok(node_id) => println!("Node {} sent Ok", node_id),
            node::NodeResponse::Error(node_id) => println!("Node {} sent Error", node_id),
            _ => panic!("Unknown message from thread"),
        }
    }
}

pub fn start_node(
    node_id: usize,
    socket_addr: net::SocketAddr,
    command_receiver: mpsc::Receiver<node::NodeCommand>,
    response_sender: mpsc::Sender<node::NodeResponse>,
) {
    println!(
        "[{}] Trying to connect to {}:{}",
        node_id,
        socket_addr.ip(),
        socket_addr.port()
    );
    let stream = net::TcpStream::connect(socket_addr).expect("Couldn't connect to remote host...");

    println!(
        "[{}] Connected to {} on port {}",
        node_id,
        socket_addr.ip(),
        socket_addr.port()
    );

    let mut node = node::Node::new(node_id, stream, command_receiver, response_sender);
    node.run();
}
