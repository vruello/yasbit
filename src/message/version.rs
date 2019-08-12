use std::net;

use crate::message;
use crate::message::MessageCommand;
use crate::network;
use crate::network::NetAddrBase;
use crate::utils;
use crate::variable_integer::VariableInteger;

const NAME: &str = "version";

#[derive(PartialEq, Debug)]
pub struct MessageVersion {
    version: u32,                       // Identifies protocol version being used by the node
    services: u64,                      // bitfield of features to be enabled for this connection
    timestamp: u64,                     // standard UNIX timestamp in seconds
    addr_recv: network::NetAddrVersion, // The network address of the node receiving this message

    // Fields below require version >= 106
    addr_from: network::NetAddrVersion, // The network address of the node emitting this message
    nonce: u64, // Node random nonce, randomly generated every time a version packet is sent.
    // This nonce is used to detect connections to self.
    user_agent: String, // User Agent (0x00 if string is 0 bytes long)
    start_height: u32,  // The last block received by the emitting node
}

impl message::MessageCommand for MessageVersion {
    fn name(&self) -> [u8; 12] {
        let mut command = [0; 12];
        for (i, c) in NAME.char_indices() {
            command[i] = c as u8;
        }
        command
    }

    fn length(&self) -> u32 {
        let user_agent_len_size = VariableInteger::new(self.user_agent.len() as u64)
            .bytes()
            .len();
        (4 + 8 + 8 + 26 + 26 + 8 + user_agent_len_size + self.user_agent.len() + 4) as u32
    }

    fn bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(&self.services.to_le_bytes());
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        bytes.extend_from_slice(self.addr_recv.bytes().as_slice());
        bytes.extend_from_slice(self.addr_from.bytes().as_slice());
        bytes.extend_from_slice(&self.nonce.to_le_bytes());
        let user_agent_length = VariableInteger::new(self.user_agent.len() as u64);
        bytes.extend_from_slice(user_agent_length.bytes().as_slice());
        bytes.extend_from_slice(self.user_agent.as_bytes());
        bytes.extend_from_slice(&self.start_height.to_le_bytes());
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        let mut index = 0;
        let version = u32::from_le_bytes(utils::clone_into_array(&bytes[index..(index + 4)]));
        index += 4;
        let services = u64::from_le_bytes(utils::clone_into_array(&bytes[index..(index + 8)]));
        index += 8;
        let timestamp = u64::from_le_bytes(utils::clone_into_array(&bytes[index..(index + 8)]));
        index += 8;

        let addr_recv = network::NetAddrVersion::from_bytes(
            &bytes[index..(index + network::NET_ADDR_VERSION_SIZE)],
        );
        index += network::NET_ADDR_VERSION_SIZE;
        let addr_from = network::NetAddrVersion::from_bytes(
            &bytes[index..(index + network::NET_ADDR_VERSION_SIZE)],
        );
        index += network::NET_ADDR_VERSION_SIZE;

        let nonce = u64::from_le_bytes(utils::clone_into_array(&bytes[index..(index + 8)]));
        index += 8;

        let (user_agent_length, user_agent_size) =
            VariableInteger::from_bytes(&bytes[index..]).unwrap();
        index += user_agent_size;
        let user_agent = std::str::from_utf8(&bytes[index..(index + (user_agent_length as usize))])
            .unwrap()
            .to_owned();
        index += user_agent_length as usize;
        let start_height = u32::from_le_bytes(utils::clone_into_array(&bytes[index..(index + 4)]));
        index += 4;
        assert_eq!(index, bytes.len());

        MessageVersion {
            version,
            services,
            timestamp,
            addr_recv,
            addr_from,
            nonce,
            user_agent,
            start_height,
        }
    }
}

impl MessageVersion {
    pub fn new(
        version: u32,
        services: u64,
        timestamp: u64,
        addr_recv: network::NetAddrVersion,
        addr_from: network::NetAddrVersion,
        nonce: u64,
        user_agent: String,
        start_height: u32,
    ) -> Self {
        MessageVersion {
            version,
            services,
            timestamp,
            addr_recv,
            addr_from,
            nonce,
            user_agent,
            start_height,
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_message_version() {
        let addr: net::Ipv4Addr = "0.0.0.0".parse().unwrap();
        let message = MessageVersion::new(
            0xea62,
            message::NODE_NETWORK,
            1355854353, // Tue Dec 18 10:12:33 PST 2012
            network::NetAddrVersion::new(message::NODE_NETWORK, addr.to_ipv6_mapped(), 0),
            network::NetAddrVersion::new(message::NODE_NETWORK, addr.to_ipv6_mapped(), 0),
            0x6517E68C5DB32E3B,
            "/Satoshi:0.7.2/".to_string(),
            0x033EC0,
        );

        assert_eq!(message.length(), 100);
        assert_eq!(hex::encode(message.name()), "76657273696f6e0000000000");
        assert_eq!(
            "62ea0000010000000000000011b2d050000000000100000000000000000000000\
             00000000000ffff000000000000010000000000000000000000000000000000fff\
             f0000000000003b2eb35d8ce617650f2f5361746f7368693a302e372e322fc03e0\
             300",
            hex::encode(message.bytes())
        );
        assert_eq!(message, MessageVersion::from_bytes(&message.bytes()));
    }
}
