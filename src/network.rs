use crate::message;
use crate::message::MessageCommand;
use crate::rand::RngCore;
use crate::utils;

use std::io::{Read, Write};
use std::net;
use std::sync::mpsc;
use std::thread;
use std::time::SystemTime;

pub trait NetAddrBase {
    fn bytes(&self) -> Vec<u8>;
    fn from_bytes(_: &[u8]) -> Self;
}

pub const NET_ADDR_VERSION_SIZE: usize = 26;
pub const NET_ADDR_SIZE: usize = NET_ADDR_VERSION_SIZE + 4;

#[derive(PartialEq, Debug)]
pub struct NetAddr {
    time: u32,
    net_addr_version: NetAddrVersion,
}

impl NetAddrBase for NetAddr {
    fn bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.time.to_le_bytes());
        bytes.extend_from_slice(self.net_addr_version.bytes().as_slice());
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        let mut index = 0;
        let time = u32::from_le_bytes(utils::clone_into_array(&bytes[index..(index + 4)]));
        index += 4;
        let net_addr_version = NetAddrVersion::from_bytes(&bytes[index..]);
        NetAddr {
            time,
            net_addr_version,
        }
    }
}

impl NetAddr {
    pub fn new(time: u32, services: u64, ip: net::Ipv6Addr, port: u16) -> Self {
        NetAddr {
            time,
            net_addr_version: NetAddrVersion::new(services, ip, port),
        }
    }
}

#[derive(PartialEq, Debug)]
pub struct NetAddrVersion {
    services: u64,
    ip: net::Ipv6Addr,
    port: u16,
}

impl NetAddrBase for NetAddrVersion {
    fn bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.services.to_le_bytes());
        bytes.extend_from_slice(&self.ip.octets());
        // Port is in network format: big endian
        bytes.extend_from_slice(&self.port.to_be_bytes());
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        let mut index = 0;
        let services = u64::from_le_bytes(utils::clone_into_array(&bytes[index..(index + 8)]));
        index += 8;
        let ip = net::Ipv6Addr::from(utils::clone_into_array::<[u8; 16], u8>(
            &bytes[index..(index + 16)],
        ));
        index += 16;
        let port = u16::from_be_bytes(utils::clone_into_array(&bytes[index..(index + 2)]));

        NetAddrVersion { services, ip, port }
    }
}

impl NetAddrVersion {
    pub fn new(services: u64, ip: net::Ipv6Addr, port: u16) -> Self {
        NetAddrVersion { services, ip, port }
    }
}

#[derive(PartialEq, Debug, Clone)]
pub enum ConnectionState {
    CLOSED,
    VER_RECEIVED,
    VER_SENT,
    VERACK_RECEIVED,
    ESTABLISHED,
}

pub struct Node {
    stream: net::TcpStream,
    state: ConnectionState,
    t_cw: mpsc::Sender<Vec<u8>>,
    r_rc: mpsc::Receiver<message::MessageType>,
}

impl Node {
    pub fn new(stream: net::TcpStream) -> Self {
        let input_stream = stream.try_clone().unwrap();
        let output_stream = stream.try_clone().unwrap();

        let (t_cw, r_cw) = mpsc::channel();
        let (t_rc, r_rc) = mpsc::channel();

        thread::spawn(move || reader(input_stream, t_rc));
        thread::spawn(move || writer(output_stream, r_cw));

        Node {
            state: ConnectionState::CLOSED,
            stream,
            t_cw,
            r_rc,
        }
    }

    pub fn connect(&mut self) {
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
            NetAddrVersion::new(message::NODE_NETWORK, node_addr, port),
            NetAddrVersion::new(message::NODE_NETWORK, my_addr.to_ipv6_mapped(), 0),
            u64::from_le_bytes(data),
            "/yasbit:0.1.0/".to_string(),
            0,
            true,
        );
        println!("Sending version message : {:?}", version);
        let message = message::Message::new(message::MAGIC_MAIN, version);
        self.t_cw.send(message.bytes()).unwrap();
        self.state = ConnectionState::VER_SENT;

        // This thread is the controller
        loop {
            let message_type = self.r_rc.recv().unwrap();
            // Do something with the message
            let state = self.handle_message(message_type);
            if state != self.state {
                println!("State updated: {:?} -> {:?}", self.state, state);
                self.state = state;
            }
        }
    }

    pub fn handle_message(&self, message_type: message::MessageType) -> ConnectionState {
        let t_cw = &self.t_cw;
        match message_type {
            message::MessageType::Alert(mess) => {
                display_message(&mess.command);
                mess.command.handle(self.state.clone(), &t_cw)
            }
            message::MessageType::Version(mess) => {
                display_message(&mess.command);
                mess.command.handle(self.state.clone(), &t_cw)
            }
            message::MessageType::Verack(mess) => {
                display_message(&mess.command);
                mess.command.handle(self.state.clone(), &t_cw)
            }
            message::MessageType::GetAddr(mess) => {
                display_message(&mess.command);
                mess.command.handle(self.state.clone(), &t_cw)
            }
            message::MessageType::Addr(mess) => {
                display_message(&mess.command);
                mess.command.handle(self.state.clone(), &t_cw)
            }
            message::MessageType::Ping(mess) => {
                display_message(&mess.command);
                mess.command.handle(self.state.clone(), &t_cw)
            }
            message::MessageType::Pong(mess) => {
                display_message(&mess.command);
                mess.command.handle(self.state.clone(), &t_cw)
            }
            message::MessageType::GetHeaders(mess) => {
                display_message(&mess.command);
                mess.command.handle(self.state.clone(), &t_cw)
            }
            message::MessageType::FeeFilter(mess) => {
                display_message(&mess.command);
                mess.command.handle(self.state.clone(), &t_cw)
            }
            message::MessageType::SendHeaders(mess) => {
                display_message(&mess.command);
                mess.command.handle(self.state.clone(), &t_cw)
            }
            message::MessageType::Inv(mess) => {
                display_message(&mess.command);
                mess.command.handle(self.state.clone(), &t_cw)
            }
            message::MessageType::GetBlocks(mess) => {
                display_message(&mess.command);
                mess.command.handle(self.state.clone(), &t_cw)
            }
            message::MessageType::GetData(mess) => {
                display_message(&mess.command);
                mess.command.handle(self.state.clone(), &t_cw)
            }
            message::MessageType::NotFound(mess) => {
                display_message(&mess.command);
                mess.command.handle(self.state.clone(), &t_cw)
            }
        }
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

fn display_message<T: message::MessageCommand + std::fmt::Debug>(command: &T) {
    println!(
        "Received {} message: {:?}",
        std::str::from_utf8(&command.name()).unwrap(),
        command
    );
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_net_addr_version() {
        let net_addr_version = NetAddrVersion::new(
            message::NODE_NETWORK,
            net::Ipv4Addr::new(10, 0, 0, 1).to_ipv6_mapped(),
            8333,
        );

        assert_eq!(
            "010000000000000000000000000000000000ffff0a000001208d",
            hex::encode(net_addr_version.bytes())
        );

        assert_eq!(
            net_addr_version,
            NetAddrVersion::from_bytes(&net_addr_version.bytes())
        );

        let net_addr_version =
            NetAddrVersion::new(message::NODE_NETWORK, "::ffff:a00:1".parse().unwrap(), 8333);

        assert_eq!(
            "010000000000000000000000000000000000ffff0a000001208d",
            hex::encode(net_addr_version.bytes())
        );

        assert_eq!(
            net_addr_version,
            NetAddrVersion::from_bytes(&net_addr_version.bytes())
        );
    }

    #[test]
    fn test_net_addr() {
        let net_addr = NetAddr::new(
            1563472788, // time
            message::NODE_NETWORK,
            net::Ipv4Addr::new(10, 0, 0, 1).to_ipv6_mapped(),
            8333,
        );

        assert_eq!(
            "94b3305d010000000000000000000000000000000000ffff0a000001208d",
            hex::encode(net_addr.bytes())
        );
        assert_eq!(net_addr, NetAddr::from_bytes(&net_addr.bytes()));

        let net_addr = NetAddr::new(
            1563472788, // time
            message::NODE_NETWORK,
            "::ffff:a00:1".parse().unwrap(),
            8333,
        );

        assert_eq!(
            "94b3305d010000000000000000000000000000000000ffff0a000001208d",
            hex::encode(net_addr.bytes())
        );
        assert_eq!(net_addr, NetAddr::from_bytes(&net_addr.bytes()));
    }
}
