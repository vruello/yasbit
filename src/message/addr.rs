use std::net;

use crate::message;
use crate::message::MessageCommand;
use crate::network;
use crate::network::NetAddrBase;
use crate::variable_integer::VariableInteger;

const NAME: &str = "addr";

#[derive(Debug, PartialEq)]
pub struct MessageAddr {
    addr_list: Vec<network::NetAddr>,
}

impl message::MessageCommand for MessageAddr {
    fn name(&self) -> [u8; 12] {
        let mut command = [0; 12];
        for (i, c) in NAME.char_indices() {
            command[i] = c as u8;
        }
        command
    }

    fn length(&self) -> u32 {
        let addr_list_len = self.addr_list.len();
        let addr_list_len_size = VariableInteger::new(addr_list_len as u64).bytes().len();
        (addr_list_len_size + (addr_list_len * network::NET_ADDR_SIZE)) as u32
    }

    fn bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        let length = VariableInteger::new(self.addr_list.len() as u64);
        bytes.extend_from_slice(length.bytes().as_slice());
        for addr in self.addr_list.iter() {
            bytes.extend_from_slice(&addr.bytes());
        }
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        let mut index = 0;
        let (addr_list_len, addr_list_len_size) =
            VariableInteger::from_bytes(&bytes[index..]).unwrap();
        index += addr_list_len_size;

        let mut addr_list = Vec::new();
        for _ in 0..addr_list_len {
            let addr =
                network::NetAddr::from_bytes(&bytes[index..(index + network::NET_ADDR_SIZE)]);
            index += network::NET_ADDR_SIZE;
            addr_list.push(addr);
        }

        MessageAddr { addr_list }
    }
}

impl MessageAddr {
    pub fn new(addr_list: Vec<network::NetAddr>) -> Self {
        MessageAddr { addr_list }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_addr() {
        let addr_list = vec![
            network::NetAddr::new(
                12345,
                message::NODE_NETWORK,
                net::Ipv4Addr::new(10, 0, 0, 1).to_ipv6_mapped(),
                8333,
            ),
            network::NetAddr::new(
                98765,
                message::NODE_NETWORK,
                net::Ipv6Addr::new(0x2000, 0xb23d, 0xc20a, 0xd, 0, 0xffff, 0x20, 0x999a),
                9999,
            ),
        ];
        let message_addr = MessageAddr::new(addr_list);

        assert_eq!(
            message_addr.name(),
            ['a' as u8, 'd' as u8, 'd' as u8, 'r' as u8, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            message_addr.length() as usize,
            1 + network::NET_ADDR_SIZE * 2
        );
        assert_eq!(message_addr.bytes().len(), message_addr.length() as usize);
        assert_eq!(message_addr, MessageAddr::from_bytes(&message_addr.bytes()));
    }
}
