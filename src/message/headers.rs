use crate::block;
use crate::message;
use crate::message::MessageCommand;
use crate::node;
use crate::variable_integer::VariableInteger;

const NAME: &str = "headers";

#[derive(Debug, PartialEq)]
pub struct MessageHeaders {
    headers: Vec<MessageBlockHeader>,
}

#[derive(Debug, PartialEq)]
pub struct MessageBlockHeader {
    header: block::BlockHeader,
    txn_count: u64,
}

impl message::MessageCommand for MessageHeaders {
    fn name(&self) -> [u8; 12] {
        let mut command = [0; 12];
        for (i, c) in NAME.char_indices() {
            command[i] = c as u8;
        }
        command
    }

    fn length(&self) -> u32 {
        let headers_len = self.headers.len();
        let headers_len_size = VariableInteger::new(headers_len as u64).bytes().len();

        let mut res = headers_len_size;
        for header in &self.headers {
            res += block::BlockHeader::length();
            res += VariableInteger::new(header.txn_count as u64).bytes().len();
        }
        res as u32
    }

    fn bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        let length = VariableInteger::new(self.headers.len() as u64);
        bytes.extend_from_slice(length.bytes().as_slice());

        for header in &self.headers {
            bytes.extend_from_slice(&header.header.bytes());
            let txn_count = VariableInteger::new(header.txn_count as u64);
            bytes.extend_from_slice(txn_count.bytes().as_slice());
        }
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        let mut index = 0;

        let (headers_len, headers_len_size) = VariableInteger::from_bytes(&bytes).unwrap();
        index += headers_len_size;

        let mut headers = Vec::with_capacity(headers_len as usize);

        for _ in 0..headers_len {
            let next_size = block::BlockHeader::length();
            let header = block::BlockHeader::from_bytes(&bytes[index..(index + next_size)]);
            index += next_size;
            let (txn_count, txn_count_size) = VariableInteger::from_bytes(&bytes[index..]).unwrap();
            index += txn_count_size;

            headers.push(MessageBlockHeader { header, txn_count });
        }

        Self { headers }
    }

    fn handle(&self, node: &mut node::Node) {}
}

impl MessageHeaders {
    pub fn new(headers: Vec<MessageBlockHeader>) -> Self {
        Self { headers }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// This test is based on
    /// https://www.blockchain.com/btc/block/00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048
    fn test_message_headers_block_1() {
        let bytes = vec![
            1, 1, 0, 0, 0, 111, 226, 140, 10, 182, 241, 179, 114, 193, 166, 162, 70, 174, 99, 247,
            79, 147, 30, 131, 101, 225, 90, 8, 156, 104, 214, 25, 0, 0, 0, 0, 0, 152, 32, 81, 253,
            30, 75, 167, 68, 187, 190, 104, 14, 31, 238, 20, 103, 123, 161, 163, 195, 84, 11, 247,
            177, 205, 182, 6, 232, 87, 35, 62, 14, 97, 188, 102, 73, 255, 255, 0, 29, 1, 227, 98,
            153, 0,
        ];
        let message = MessageHeaders::from_bytes(&bytes);

        assert_eq!(bytes, message.bytes());
    }

    #[test]
    /// This test is based on the genesis block
    /// https://www.blockchain.com/fr/btc/block/000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
    fn test_message_headers_genesis() {
        let block = block::genesis_block();
        let headers = vec![MessageBlockHeader {
            header: block.header.clone(),
            txn_count: 0,
        }];

        let messageHeaders = MessageHeaders::new(headers);
        assert_eq!(
            messageHeaders.name(),
            [
                'h' as u8, 'e' as u8, 'a' as u8, 'd' as u8, 'e' as u8, 'r' as u8, 's' as u8, 0, 0,
                0, 0, 0
            ]
        );
        assert_eq!(messageHeaders.headers.len(), 1);
        assert_eq!(messageHeaders.headers[0].header, block.header);
        assert_eq!(messageHeaders.headers[0].txn_count, 0);

        assert_eq!(
            messageHeaders,
            MessageHeaders::from_bytes(&messageHeaders.bytes())
        );
    }
}
