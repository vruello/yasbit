extern crate hex;
extern crate rand;
mod block;
mod crypto;
mod merkle_tree;
mod message;
mod network;
mod node;
mod script;
mod storage;
mod transaction;
mod utils;
mod variable_integer;

use crate::crypto::Hashable;
use dns_lookup::lookup_host;
use std::collections::HashSet;
use std::net;
use std::sync::mpsc;
use std::thread;

#[derive(Debug)]
struct GlobalState {
    nodes: Vec<node::NodeHandle>,
    known_active_nodes: HashSet<network::NetAddr>,
    sync_node_id: Option<node::NodeId>,
}

pub fn run() {
    // Initialize DBs
    let mut storage = storage::Storage::new(
        "/var/tmp/yasbit/blocks.db",
        "/var/tmp/yasbit/transactions.db",
    );

    // Load peers
    let mut addrs = lookup_host("seed.bitcoin.sipa.be").unwrap();
    addrs.truncate(8);

    log::info!("Peers: {:?}", addrs);

    let mut state = GlobalState {
        nodes: vec![],
        known_active_nodes: HashSet::new(),
        sync_node_id: None,
    };

    let (response_sender, response_receiver) = mpsc::channel();

    for addr in &addrs {
        let (command_sender, command_receiver) = mpsc::channel();
        let node_id = state.nodes.len();
        state
            .nodes
            .push(node::NodeHandle::new(node_id, command_sender));
        let node_response_sender = response_sender.clone();
        let node_sock_addr = net::SocketAddr::new(*addr, 8333);
        thread::spawn(move || {
            start_node(
                node_id,
                node_sock_addr,
                command_receiver,
                node_response_sender,
            )
        });
    }

    loop {
        log::debug!("Global State: {:?}", state);
        let response = response_receiver.recv().unwrap();

        let node_handle = match get_node_handle(&mut state.nodes, &response.node_id) {
            Some(handle) => handle,
            None => {
                log::warn!("Can not get node_handle: {:?}", response);
                continue;
            }
        };

        log::debug!("Received response from node {:?}", node_handle);

        match response.content {
            node::NodeResponseContent::Connected => {
                if let node::NodeState::CONNECTING(_) = node_handle.state() {
                    node_handle.send(node::NodeCommand::SendMessage(
                        message::MessageType::GetAddr(message::Message::new(
                            message::MAGIC_MAIN,
                            message::getaddr::MessageGetAddr::new(),
                        )),
                    ));
                    node_handle.set_state(node::NodeState::UPDATING_PEERS);
                } else {
                    log::warn!("Unexpected Connected message");
                }
            }
            node::NodeResponseContent::Addrs(addrs) => {
                for addr in &addrs {
                    state.known_active_nodes.insert(addr.clone());
                }

                if let node::NodeState::UPDATING_PEERS = node_handle.state() {
                    if state.sync_node_id.is_none() {
                        state.sync_node_id = Some(response.node_id.clone());
                        log::info!("Node {} becomes the sync node", response.node_id);
                        node_handle.set_state(node::NodeState::UPDATING_BLOCKS);
                        node_handle.send(node::NodeCommand::SendMessage(
                            message::MessageType::GetHeaders(message::Message::new(
                                message::MAGIC_MAIN,
                                message::getheaders::MessageGetHeaders::new(
                                    70013,
                                    vec![block::genesis_block().hash()], // TODO
                                    [0; 32], // Get at most headers as possible
                                ),
                            )),
                        ));
                    }
                } else {
                    log::warn!("Unexpected Addrs message");
                }
            }
            _ => log::warn!("Unknown message from thread"),
        };
    }
}

fn get_node_handle<'a>(
    nodes: &'a mut Vec<node::NodeHandle>,
    node_id: &node::NodeId,
) -> Option<&'a mut node::NodeHandle> {
    // FIXME
    // This is a dumb implementation. Maybe node_id should not be
    // the index of the node in nodes...
    nodes.iter_mut().nth(*node_id)
}

fn start_node(
    node_id: usize,
    socket_addr: net::SocketAddr,
    command_receiver: mpsc::Receiver<node::NodeCommand>,
    response_sender: mpsc::Sender<node::NodeResponse>,
) {
    log::debug!(
        "[{}] Trying to connect to {}:{}",
        node_id,
        socket_addr.ip(),
        socket_addr.port()
    );
    let stream = net::TcpStream::connect(socket_addr).expect("Couldn't connect to remote host...");

    log::debug!(
        "[{}] Connected to {} on port {}",
        node_id,
        socket_addr.ip(),
        socket_addr.port()
    );

    let mut node = node::Node::new(node_id, stream, command_receiver, response_sender);
    node.run();
}
