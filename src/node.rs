use crate::block;
use crate::config::Config;
use crate::crypto;
use crate::message;
use crate::message::inv_base::{InvVect, MSG_BLOCK};
use crate::message::MessageCommand;
use crate::network;
use crate::rand::RngCore;

use crate::crypto::Hashable;
use std::cmp::min;
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net;
use std::rc::Rc;
use std::sync::mpsc;
use std::thread;
use std::time::SystemTime;

pub type NodeId = usize;

const MAX_DOWNLOADING_BLOCKS: usize = 16;

#[derive(Debug, Clone)]
pub struct NodeHandle {
    id: NodeId,
    command_sender: mpsc::Sender<NodeCommand>,
    state: NodeState,
    download_current: Vec<crypto::Hash32>,
}

impl NodeHandle {
    pub fn new(id: NodeId, command_sender: mpsc::Sender<NodeCommand>) -> Self {
        NodeHandle {
            id,
            command_sender,
            state: NodeState::CONNECTING(ConnectionState::CLOSED),
            download_current: Vec::new(),
        }
    }

    pub fn send(&self, command: NodeCommand) {
        self.command_sender.send(command).unwrap();
    }

    pub fn state(&self) -> &NodeState {
        &self.state
    }

    pub fn set_state(&mut self, state: NodeState) {
        log::debug!("Update state: {:?} => {:?}", self.state, state);
        self.state = state;
    }

    pub fn id(&self) -> NodeId {
        self.id
    }

    pub fn mark_downloaded(&mut self, block: &block::Block) {
        match self
            .download_current
            .iter()
            .position(|elt| elt == &block.hash())
        {
            Some(index) => {
                log::debug!("[{}] Found {:?} at index {}", self.id, &block.hash(), index);
                self.download_current.swap_remove(index);
            }
            None => log::warn!("[{}] Block {:?} was not asked", self.id, block.hash()),
        }
    }

    pub fn download_next(
        &mut self,
        config: &Config,
        download_queue: &mut VecDeque<crypto::Hash32>,
    ) -> bool {
        match &self.state {
            NodeState::UPDATING_BLOCKS => {}
            _ => {
                log::warn!(
                    "[{}] Not ready to download. Current state is {:?}",
                    self.id,
                    &self.state
                );
                return false;
            }
        };

        log::debug!(
            "[{}] download_next called. download_current len = {}. current state = {:?}",
            self.id,
            self.download_current.len(),
            self.state
        );

        if self.download_current.is_empty() {
            log::debug!(
                "[{:?}] Node is ready to download! Download queue len: {}",
                self.id,
                download_queue.len()
            );
            let count_to_download = min(MAX_DOWNLOADING_BLOCKS, download_queue.len());

            if count_to_download == 0 {
                log::debug!("[{}] Download queue is empty", self.id);
                return false;
            }

            for _ in 0..count_to_download {
                self.download_current
                    .push(download_queue.pop_front().unwrap());
            }

            log::debug!(
                "[{}] To download ({}): {:?}, queue size: {}",
                self.id,
                self.download_current.len(),
                self.download_current,
                download_queue.len()
            );

            // Send message
            self.send(NodeCommand::SendMessage(message::MessageType::GetData(
                message::Message::new(
                    config.magic,
                    message::getdata::MessageGetData::new(
                        self.download_current
                            .iter()
                            .map(|elt| InvVect {
                                hash_type: MSG_BLOCK,
                                hash: *elt,
                            })
                            .collect(),
                    ),
                ),
            )));
            log::debug!(
                "[{}] Current download len: {}",
                self.id,
                self.download_current.len()
            );
        } else {
            log::warn!("[{}] Already downloading", self.id,);
        }
        true
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum NodeState {
    CONNECTING(ConnectionState),
    UPDATING_PEERS,
    UPDATING_BLOCKS,
}

#[derive(Debug)]
pub enum NodeCommand {
    SendMessage(message::MessageType),
}

#[derive(Debug)]
pub struct NodeResponse {
    pub node_id: NodeId,
    pub content: NodeResponseContent,
}

#[derive(Debug)]
pub enum NodeResponseContent {
    Connected,
    Addrs(Vec<network::NetAddr>),
    Headers(Vec<block::BlockHeader>),
    Block(block::Block),
}

#[derive(PartialEq, Debug, Clone)]
pub enum ConnectionState {
    CLOSED,
    VER_RECEIVED,
    VER_SENT,
    VERACK_RECEIVED,
    ESTABLISHED,
}

pub enum CommandOrMessageType {
    Command(NodeCommand),
    MessageType(message::MessageType),
}

pub struct Node {
    node_id: usize,
    stream: net::TcpStream,
    state: ConnectionState,
    writer_receiver: mpsc::Receiver<CommandOrMessageType>,
    response_sender: mpsc::Sender<NodeResponse>,
}

impl Node {
    pub fn new(
        node_id: usize,
        stream: net::TcpStream,
        command_receiver: mpsc::Receiver<NodeCommand>,
        response_sender: mpsc::Sender<NodeResponse>,
    ) -> Self {
        let input_stream = stream.try_clone().unwrap();

        let (writer_sender, writer_receiver) = mpsc::channel();
        let command_writer_sender = writer_sender.clone();

        thread::spawn(move || reader(input_stream, writer_sender));
        // thread::spawn(move || writer(output_stream, r_cw));
        thread::spawn(move || command(command_receiver, command_writer_sender));

        Node {
            node_id,
            state: ConnectionState::CLOSED,
            stream,
            writer_receiver,
            response_sender,
        }
    }

    pub fn run(&mut self, config: &Config) {
        // Init connection by sending version message
        let my_addr: net::Ipv4Addr = "0.0.0.0".parse().unwrap();
        let node_addr: net::Ipv6Addr = match self.stream.peer_addr().unwrap() {
            net::SocketAddr::V4(addr) => addr.ip().to_ipv6_mapped(),
            net::SocketAddr::V6(addr) => addr.ip().clone(),
        };
        let port: u16 = self.stream.peer_addr().unwrap().port();
        let mut data = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut data);
        let version = message::version::MessageVersion::new(
            70013,
            message::NODE_NETWORK,
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs() as u64,
            network::NetAddrVersion::new(message::NODE_NETWORK, node_addr, port),
            network::NetAddrVersion::new(message::NODE_NETWORK, my_addr.to_ipv6_mapped(), 0),
            u64::from_le_bytes(data),
            "/yasbit:0.1.0/".to_string(),
            0,
            true,
        );
        log::debug!(
            "[{}]: Sending version message : {:?}",
            self.node_id,
            version
        );
        let message = message::Message::new(config.magic, version);
        self.stream.write(&message.bytes()).unwrap();
        self.stream.flush().unwrap();

        self.state = ConnectionState::VER_SENT;

        // This is the writer thread, the main thread managing this node
        // It reads from reader and command and eventually send messages
        // to the peer
        loop {
            match self.writer_receiver.recv().unwrap() {
                CommandOrMessageType::MessageType(message_type) => {
                    self.handle_message(config, message_type);
                }
                CommandOrMessageType::Command(node_command) => {
                    self.handle_command(node_command);
                }
            }
        }
    }

    pub fn handle_command(&mut self, node_command: NodeCommand) {
        match node_command {
            NodeCommand::SendMessage(message) => {
                log::debug!("[{}] Send message: {:?}", self.node_id, &message);
                self.stream.write(&message.bytes()).unwrap();
                self.stream.flush().unwrap();
            }
        }
    }

    pub fn handle_message(&mut self, config: &Config, message_type: message::MessageType) {
        match message_type {
            message::MessageType::Alert(mess) => {
                display_message(&self.node_id, &mess.command);
                mess.command.handle(self, config)
            }
            message::MessageType::Version(mess) => {
                display_message(&self.node_id, &mess.command);
                mess.command.handle(self, config)
            }
            message::MessageType::Verack(mess) => {
                display_message(&self.node_id, &mess.command);
                mess.command.handle(self, config)
            }
            message::MessageType::GetAddr(mess) => {
                display_message(&self.node_id, &mess.command);
                mess.command.handle(self, config)
            }
            message::MessageType::Addr(mess) => {
                display_message(&self.node_id, &mess.command);
                mess.command.handle(self, config)
            }
            message::MessageType::Ping(mess) => {
                display_message(&self.node_id, &mess.command);
                mess.command.handle(self, config)
            }
            message::MessageType::Pong(mess) => {
                display_message(&self.node_id, &mess.command);
                mess.command.handle(self, config)
            }
            message::MessageType::GetHeaders(mess) => {
                display_message(&self.node_id, &mess.command);
                mess.command.handle(self, config)
            }
            message::MessageType::FeeFilter(mess) => {
                display_message(&self.node_id, &mess.command);
                mess.command.handle(self, config)
            }
            message::MessageType::SendHeaders(mess) => {
                display_message(&self.node_id, &mess.command);
                mess.command.handle(self, config)
            }
            message::MessageType::Inv(mess) => {
                display_message(&self.node_id, &mess.command);
                mess.command.handle(self, config)
            }
            message::MessageType::GetBlocks(mess) => {
                display_message(&self.node_id, &mess.command);
                mess.command.handle(self, config)
            }
            message::MessageType::GetData(mess) => {
                display_message(&self.node_id, &mess.command);
                mess.command.handle(self, config)
            }
            message::MessageType::NotFound(mess) => {
                display_message(&self.node_id, &mess.command);
                mess.command.handle(self, config)
            }
            message::MessageType::Headers(mess) => {
                // display_message(&self.node_id, &mess.command);
                log::debug!(
                    "[{}] Received {} message",
                    self.node_id,
                    std::str::from_utf8(&mess.command.name()).unwrap(),
                );
                mess.command.handle(self, config)
            }
            message::MessageType::Block(mess) => {
                display_message(&self.node_id, &mess.command);
                mess.command.handle(self, config)
            }
        }
    }

    pub fn id(&self) -> &NodeId {
        &self.node_id
    }

    pub fn stream(&mut self) -> &mut net::TcpStream {
        &mut self.stream
    }

    pub fn connection_state(&self) -> &ConnectionState {
        &self.state
    }

    pub fn set_connection_state(&mut self, state: ConnectionState) {
        self.state = state;
    }

    pub fn send_response(
        &mut self,
        content: NodeResponseContent,
    ) -> Result<(), mpsc::SendError<NodeResponse>> {
        self.response_sender.send(NodeResponse {
            node_id: self.node_id,
            content,
        })
    }
}

fn command(
    command_receiver: mpsc::Receiver<NodeCommand>,
    command_writer_sender: mpsc::Sender<CommandOrMessageType>,
) {
    loop {
        let command = command_receiver.recv().unwrap();
        command_writer_sender
            .send(CommandOrMessageType::Command(command))
            .unwrap();
    }
}

fn reader(mut stream: net::TcpStream, t_rc: mpsc::Sender<CommandOrMessageType>) {
    let mut bytes = Vec::new();
    let mut buffer = [0 as u8; 100];
    let mut remaining_bytes = 0;
    loop {
        let received_bytes = stream.read(&mut buffer).unwrap();
        if received_bytes == 0 {
            log::info!("Remote {:?} closed connection", stream.peer_addr().unwrap());
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
                    t_rc.send(CommandOrMessageType::MessageType(message_type))
                        .unwrap();
                }
                Err(message::ParseError::Partial(needed)) => {
                    remaining_bytes = needed;
                }
                Err(err) => {
                    log::warn!(
                        "Could not parse received message: {:?}.\n Message received: {:?}",
                        &err,
                        bytes
                    );
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

fn display_message<T: message::MessageCommand + std::fmt::Debug>(node_id: &NodeId, command: &T) {
    log::debug!(
        "[{}] Received {} message: {:?}",
        node_id,
        std::str::from_utf8(&command.name()).unwrap(),
        command
    );
}
