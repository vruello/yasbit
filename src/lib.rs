extern crate hex;
extern crate rand;
mod block;
mod config;
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

const PEERS_NUMBER: usize = 8;
const MAX_HEADERS: usize = 2000;

#[derive(Debug)]
struct GlobalState {
    nodes: Vec<node::NodeHandle>,
    known_active_nodes: HashSet<network::NetAddr>,
    sync_node_id: Option<node::NodeId>,
    download_queue: VecDeque<crypto::Hash32>,
}

pub enum ControllerMessage {
    NodeResponse(node::NodeResponse),
    ValiderResponse(valider::ValiderMessage),
}

fn get_peers_from_dns(config: &config::Config, size: usize) -> Vec<std::net::IpAddr> {
    // Load peers
    let mut addrs = Vec::new();
    for seed in &config.dns_seeds {
        log::debug!("Resolve {}", seed);
        match lookup_host(&seed) {
            Ok(ips) => {
                if !ips.is_empty() {
                    addrs = ips;
                    break;
                }
            }
            _ => (),
        }
    }
    addrs.truncate(size);
    log::info!("Peers: {:?}", addrs);
    addrs
}

pub fn run() {
    let config = config::test_config();

    // Initialize DBs
    let mut storage = storage::Storage::new(
        "/var/tmp/yasbit/blocks.db",
        "/var/tmp/yasbit/transactions.db",
        "/var/tmp/yasbit/chain.db",
        "/var/tmp/yasbit/blocks/",
    );

    match storage.has_block(config.genesis_block.hash()) {
        Ok(true) => log::info!(
            "Genesis block {} already exists.",
            hex::encode(config.genesis_block.hash())
        ),
        Ok(false) => {
            storage.store_block(&config.genesis_block).unwrap();
            log::info!(
                "Genesis block {} not found.",
                hex::encode(config.genesis_block.hash())
            );
        }
        Err(err) => {
            log::error!("Storage error: {:?}.", err);
            return;
        }
    }

    let addrs = get_peers_from_dns(&config, PEERS_NUMBER);

    let mut state = GlobalState {
        nodes: vec![],
        known_active_nodes: HashSet::new(),
        sync_node_id: None,
        download_queue: VecDeque::new(),
    };

    let (controller_sender, controller_receiver) = mpsc::channel();

    for addr in &addrs {
        let (command_sender, command_receiver) = mpsc::channel();
        let node_id = state.nodes.len();
        state
            .nodes
            .push(node::NodeHandle::new(node_id, command_sender));
        let node_controller_sender = controller_sender.clone();
        let node_sock_addr = net::SocketAddr::new(*addr, config.port);
        let node_config = config.clone();
        thread::spawn(move || {
            start_node(
                node_id,
                node_sock_addr,
                command_receiver,
                node_controller_sender,
                node_config,
            )
        });
    }

    // Spawn valider thread
    let (mut valider_sender, valider_receiver) = mpsc::channel();
    let valider_sender_timeout = valider_sender.clone();
    let valider_controller_sender = controller_sender.clone();
    thread::spawn(move || {
        valider::run(
            storage,
            valider_sender_timeout.clone(),
            valider_receiver,
            valider_controller_sender,
        )
    });
    log::info!("Valider thread spawned");

    loop {
        log::trace!("Global State: {:?}", state);
        let message = controller_receiver.recv().unwrap();

        match message {
            ControllerMessage::NodeResponse(response) => handle_node_response(
                &mut state,
                &config,
                &mut valider_sender,
                &controller_sender,
                response,
            ),
            ControllerMessage::ValiderResponse(valider_message) => {
                handle_valider_message(&mut state, &config, valider_message, &controller_sender)
            }
        };
    }
}

fn node_restart_with_new_peer(
    state: &mut GlobalState,
    config: &config::Config,
    controller_sender: &mpsc::Sender<ControllerMessage>,
    node_id: node::NodeId,
) {
    log::info!("[{}] Restart node", node_id);

    let node_handle = match get_node_handle(&mut state.nodes, &node_id) {
        Some(handle) => handle,
        None => {
            log::warn!("Can not get node_handle: {}", node_id);
            return;
        }
    };
    // Kill this node
    node_handle
        .send(node::NodeCommand::Kill)
        .unwrap_or_default();

    // Push front on the download queue the current downloads of
    // the old node so that the other nodes will be able to download
    // these blocks
    loop {
        if let Some(hash) = node_handle.download_current_pop() {
            state.download_queue.push_front(hash);
        } else {
            break;
        }
    }

    // Create a new mpsc channel to communicate with the new peer
    let (command_sender, command_receiver) = mpsc::channel();

    // Reset node handle
    node_handle.reset(command_sender);

    // Restart node with a new peer
    let node_id = node_handle.id();

    let (addr, port) = match state.known_active_nodes.iter().nth(0) {
        Some(active_node) => (
            net::IpAddr::from(active_node.net_addr_version.ip),
            active_node.net_addr_version.port,
        ),
        None => {
            let addrs = get_peers_from_dns(config, 1);
            if addrs.len() < 1 {
                log::error!("Could not find another peer from DNS");
                return;
            }

            (addrs[0], config.port)
        }
    };

    let node_sock_addr = net::SocketAddr::new(addr, port);
    let node_config = config.clone();
    let node_controller_sender = controller_sender.clone();
    log::info!(
        "[{}] Start communicating with a new peer: {:?}",
        node_id,
        node_sock_addr
    );
    thread::spawn(move || {
        start_node(
            node_id,
            node_sock_addr,
            command_receiver,
            node_controller_sender,
            node_config,
        )
    });

    // Send a download message to all nodes
    send_download_message(state, config);
}

fn handle_valider_message(
    state: &mut GlobalState,
    config: &config::Config,
    valider_message: valider::ValiderMessage,
    controller_sender: &mpsc::Sender<ControllerMessage>,
) {
    match valider_message {
        valider::ValiderMessage::Timeout(hash) => {
            log::debug!("Timeout for block {} !!!", hex::encode(hash));

            let node_handle = match state
                .nodes
                .iter()
                .find(move |x| (**x).is_downloading(&hash))
            {
                Some(nh) => nh,
                None => {
                    log::error!(
                        "Block {} can not be found in current downloads list.",
                        hex::encode(hash)
                    );
                    // Put hash on the top of the downloaad queue
                    state.download_queue.push_front(hash);
                    send_download_message(state, config);
                    return;
                }
            };
            node_restart_with_new_peer(state, config, controller_sender, node_handle.id());
        }
    }
}

fn handle_node_response(
    state: &mut GlobalState,
    config: &config::Config,
    valider_sender: &mut mpsc::Sender<valider::Message>,
    controller_sender: &mpsc::Sender<ControllerMessage>,
    response: node::NodeResponse,
) {
    let node_handle = match get_node_handle(&mut state.nodes, &response.node_id) {
        Some(handle) => handle,
        None => {
            log::warn!("Can not get node_handle: {:?}", response);
            return;
        }
    };

    log::debug!("Received response from node {:?}", node_handle.id());

    match response.content {
        node::NodeResponseContent::Connected => {
            if let node::NodeState::CONNECTING(_) = node_handle.state() {
                node_handle.send(node::NodeCommand::SendMessage(
                    message::MessageType::GetAddr(message::Message::new(
                        config.magic,
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
                            config.magic,
                            message::getheaders::MessageGetHeaders::new(
                                70013,
                                vec![config.genesis_block.hash()], // TODO
                                [0; 32], // Get at most headers as possible
                            ),
                        )),
                    ));
                } else {
                    // Node is not the sync node. Try to download
                    log::info!("Node {} becomes a download node", response.node_id);
                    node_handle.download_next(&config, &mut state.download_queue);
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
                return;
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

            send_download_message(state, config);

            if headers.len() == MAX_HEADERS {
                let last_hash = headers.last().unwrap().hash();
                log::debug!("Send another GetHeaders message from: {:?}", last_hash);
                let sync_node =
                    get_node_handle(&mut state.nodes, &state.sync_node_id.unwrap()).unwrap();
                sync_node.send(node::NodeCommand::SendMessage(
                    message::MessageType::GetHeaders(message::Message::new(
                        config.magic,
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
            node_handle.download_next(&config, &mut state.download_queue);
        }
        node::NodeResponseContent::ConnectionClosed => {
            log::debug!(
                "[{}] Restart node with a new peer because connection has been closed.",
                node_handle.id()
            );
            let node_id = node_handle.id();
            node_restart_with_new_peer(state, config, controller_sender, node_id);
        }
        _ => log::warn!("Unknown message from thread"),
    };
}

fn send_download_message(state: &mut GlobalState, config: &config::Config) {
    log::debug!("Send download message to nodes");
    let mut download_nodes = if state.nodes.len() > 1 {
        state
            .nodes
            .iter()
            .filter(|elt| elt.id() != state.sync_node_id.unwrap())
            .cloned()
            .collect()
    } else {
        state.nodes.clone() // FIXME Find a way to avoid cloning here
    };
    for node in download_nodes.iter_mut() {
        node.download_next(&config, &mut state.download_queue);
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
    response_sender: mpsc::Sender<ControllerMessage>,
    config: config::Config,
) {
    log::info!(
        "[{}] Trying to connect to {}:{}",
        node_id,
        socket_addr.ip(),
        socket_addr.port()
    );
    let stream = match net::TcpStream::connect(socket_addr) {
        Ok(value) => value,
        Err(_) => {
            log::error!(
                "[{}] Could not connect to {}:{}",
                node_id,
                socket_addr.ip(),
                socket_addr.port()
            );

            response_sender.send(ControllerMessage::NodeResponse(node::NodeResponse {
                node_id: node_id,
                content: node::NodeResponseContent::ConnectionClosed,
            }));
            return;
        }
    };

    log::info!(
        "[{}] Connected to {} on port {}",
        node_id,
        socket_addr.ip(),
        socket_addr.port()
    );

    let mut node = node::Node::new(node_id, stream, command_receiver, response_sender);
    node.run(&config);
}
