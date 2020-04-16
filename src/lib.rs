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
mod valider;
mod variable_integer;

use crate::crypto::Hashable;
use dns_lookup::lookup_host;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net;
use std::sync::{mpsc, Arc, Mutex, RwLock};
use std::thread;

const PEERS_NUMBER: usize = 3;
const MAX_HEADERS: usize = 2000;

#[derive(Debug)]
struct GlobalState {
    nodes: Vec<node::NodeHandle>,
    known_active_nodes: HashSet<network::NetAddr>,
    sync_node_id: Option<node::NodeId>,
    download_queue: VecDeque<crypto::Hash32>,
}

pub fn run() {
    // Initialize DBs
    let mut storage = Arc::new(storage::Storage::new(
        "/var/tmp/yasbit/blocks.db",
        "/var/tmp/yasbit/transactions.db",
        "/var/tmp/yasbit/chain.db",
    ));

    // Load peers
    let mut addrs = lookup_host("seed.bitcoin.sipa.be").unwrap();
    addrs.truncate(PEERS_NUMBER);

    log::info!("Peers: {:?}", addrs);

    let mut state = GlobalState {
        nodes: vec![],
        known_active_nodes: HashSet::new(),
        sync_node_id: None,
        download_queue: VecDeque::new(),
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

    // Spawn valider thread
    let (valider_sender, valider_receiver) = mpsc::channel();
    let valider_sender_timeout = valider_sender.clone();
    thread::spawn(move || valider::run(valider_sender_timeout.clone(), valider_receiver));
    log::info!("Valider thread spawned");

    loop {
        log::trace!("Global State: {:?}", state);
        let response = response_receiver.recv().unwrap();

        let node_handle = match get_node_handle(&mut state.nodes, &response.node_id) {
            Some(handle) => handle,
            None => {
                log::warn!("Can not get node_handle: {:?}", response);
                continue;
            }
        };

        log::debug!("Received response from node {:?}", node_handle.id());

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
                    node_handle.set_state(node::NodeState::UPDATING_BLOCKS);
                    if state.sync_node_id.is_none() {
                        state.sync_node_id = Some(response.node_id.clone());
                        log::info!("Node {} becomes the sync node", response.node_id);
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
                    } else {
                        // Node is not the sync node. Try to download
                        node_handle.download_next(&mut state.download_queue);
                    }
                } else {
                    log::warn!("Unexpected Addrs message");
                }
            }
            node::NodeResponseContent::Headers(headers) => {
                if node_handle.id() != state.sync_node_id.unwrap() {
                    log::warn!(
                        "Node {} is not the sync node but it has received Headers message.",
                        node_handle.id()
                    );
                    continue;
                }

                log::debug!(
                    "Push headers to download queue. Original lenth: {}",
                    state.download_queue.len()
                );
                for header in &headers {
                    if header.validate() {
                        state.download_queue.push_back(header.hash());
                    // log::debug!("Add {:?} to download queue", header.hash());
                    } else {
                        // TODO ???
                        log::warn!("Header is invalid: {:?}", header);
                    }
                }
                log::debug!(
                    "Final length of download queue: {}",
                    state.download_queue.len()
                );

                log::debug!("Send waiting message to valider thread.");
                valider_sender
                    .send(valider::Message::Wait(
                        headers.iter().map(|header| header.hash()).collect(),
                    ))
                    .unwrap();

                log::debug!("Send download message to nodes");
                let mut download_nodes = if PEERS_NUMBER > 1 {
                    state
                        .nodes
                        .iter()
                        .filter(|elt| elt.id() != state.sync_node_id.unwrap())
                        .map(|elt| elt.clone())
                        .collect()
                } else {
                    state.nodes.clone() // FIXME Find a way to avoid cloning here...
                };
                for node in download_nodes.iter_mut() {
                    node.download_next(&mut state.download_queue);
                }

                if headers.len() == MAX_HEADERS {
                    let last_hash = headers.last().unwrap().hash();
                    log::debug!("Send another GetHeaders message from: {:?}", last_hash);
                    let sync_node =
                        get_node_handle(&mut state.nodes, &state.sync_node_id.unwrap()).unwrap();
                    sync_node.send(node::NodeCommand::SendMessage(
                        message::MessageType::GetHeaders(message::Message::new(
                            message::MAGIC_MAIN,
                            message::getheaders::MessageGetHeaders::new(
                                70013,
                                vec![last_hash],
                                [0; 32], // Get at most headers as possible
                            ),
                        )),
                    ));
                } else {
                    log::debug!("{:?} headers received. The end?", headers.len());
                }
            }
            node::NodeResponseContent::Block(block) => {
                log::debug!("Send validate message to validate thread.");
                node_handle.mark_downloaded(&block);
                valider_sender
                    .send(valider::Message::Validate(block))
                    .unwrap();
                node_handle.download_next(&mut state.download_queue);
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
