use crate::message;
use crate::message::MessageCommand;
use crate::network;
use crate::rand::RngCore;

use std::io::{Read, Write};
use std::net;
use std::sync::mpsc;
use std::thread;
use std::time::SystemTime;

pub enum NodeCommand {}

pub enum NodeResponse {
    Ok(usize),
    Error(usize),
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

    pub fn run(&mut self) {
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
        println!(
            "[{}]: Sending version message : {:?}",
            self.node_id, version
        );
        let message = message::Message::new(message::MAGIC_MAIN, version);
        self.stream.write(&message.bytes()).unwrap();
        self.stream.flush().unwrap();

        self.state = ConnectionState::VER_SENT;

        // This is the writer thread, the main thread managing this node
        // It reads from reader and command and eventually send messages
        // to the peer
        loop {
            match self.writer_receiver.recv().unwrap() {
                CommandOrMessageType::MessageType(message_type) => {
                    self.handle_message(self.stream.try_clone().unwrap(), message_type);
                }
                CommandOrMessageType::Command(node_command) => {
                    // Do something
                }
            }
        }
    }

    pub fn handle_message(
        &mut self,
        stream: net::TcpStream,
        message_type: message::MessageType,
    ) -> ConnectionState {
        self.state = match message_type {
            message::MessageType::Alert(mess) => {
                display_message(&mess.command);
                mess.command.handle(self.state.clone(), stream)
            }
            message::MessageType::Version(mess) => {
                display_message(&mess.command);
                mess.command.handle(self.state.clone(), stream)
            }
            message::MessageType::Verack(mess) => {
                display_message(&mess.command);
                mess.command.handle(self.state.clone(), stream)
            }
            message::MessageType::GetAddr(mess) => {
                display_message(&mess.command);
                mess.command.handle(self.state.clone(), stream)
            }
            message::MessageType::Addr(mess) => {
                display_message(&mess.command);
                mess.command.handle(self.state.clone(), stream)
            }
            message::MessageType::Ping(mess) => {
                display_message(&mess.command);
                mess.command.handle(self.state.clone(), stream)
            }
            message::MessageType::Pong(mess) => {
                display_message(&mess.command);
                mess.command.handle(self.state.clone(), stream)
            }
            message::MessageType::GetHeaders(mess) => {
                display_message(&mess.command);
                mess.command.handle(self.state.clone(), stream)
            }
            message::MessageType::FeeFilter(mess) => {
                display_message(&mess.command);
                mess.command.handle(self.state.clone(), stream)
            }
            message::MessageType::SendHeaders(mess) => {
                display_message(&mess.command);
                mess.command.handle(self.state.clone(), stream)
            }
            message::MessageType::Inv(mess) => {
                display_message(&mess.command);
                mess.command.handle(self.state.clone(), stream)
            }
            message::MessageType::GetBlocks(mess) => {
                display_message(&mess.command);
                mess.command.handle(self.state.clone(), stream)
            }
            message::MessageType::GetData(mess) => {
                display_message(&mess.command);
                mess.command.handle(self.state.clone(), stream)
            }
            message::MessageType::NotFound(mess) => {
                display_message(&mess.command);
                mess.command.handle(self.state.clone(), stream)
            }
        };
        self.state.clone()
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
        // println!("{} bytes received", received_bytes);
        if received_bytes == 0 {
            println!("Remote {:?} closed connection", stream.peer_addr().unwrap());
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

fn display_message<T: message::MessageCommand + std::fmt::Debug>(command: &T) {
    println!(
        "Received {} message: {:?}",
        std::str::from_utf8(&command.name()).unwrap(),
        command
    );
}
