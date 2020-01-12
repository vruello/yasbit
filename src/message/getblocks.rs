use std::net;

use crate::crypto;
use crate::message;
use crate::message::MessageCommand;
use crate::node;
use crate::utils;
use crate::variable_integer::VariableInteger;

const NAME: &str = "getblocks";

#[derive(Debug, PartialEq)]
pub struct MessageGetBlocks {
    // the protocol version
    version: u32,
    // block locator object; newest back to genesis block (dense to start,
    // but then sparse)
    block_locator_hashes: Vec<crypto::Hash32>,
    // hash of the last desired block; set to zero to get as many blocks as possible (500)
    hash_stop: crypto::Hash32,
}

impl message::MessageCommand for MessageGetBlocks {
    fn name(&self) -> [u8; 12] {
        let mut command = [0; 12];
        for (i, c) in NAME.char_indices() {
            command[i] = c as u8;
        }
        command
    }

    fn length(&self) -> u32 {
        let block_locator_len_size = VariableInteger::new(self.block_locator_hashes.len() as u64)
            .bytes()
            .len();
        (4 + block_locator_len_size + self.block_locator_hashes.len() * 4 + 4) as u32
    }

    fn bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(&self.version.to_le_bytes());

        let block_locator_size = VariableInteger::new(self.block_locator_hashes.len() as u64);
        bytes.extend_from_slice(block_locator_size.bytes().as_slice());

        for hash in self.block_locator_hashes.iter() {
            bytes.extend_from_slice(&crypto::hash32_to_bytes(&hash));
        }

        bytes.extend_from_slice(&crypto::hash32_to_bytes(&self.hash_stop));

        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        let mut index = 0;
        let mut next_size = 4;
        let version =
            u32::from_le_bytes(utils::clone_into_array(&bytes[index..(index + next_size)]));
        index += next_size;

        let (bl_hashes_len, bl_hashes_len_size) =
            VariableInteger::from_bytes(&bytes[index..]).unwrap();
        index += bl_hashes_len_size;
        let mut block_locator_hashes = Vec::with_capacity(bl_hashes_len as usize);
        next_size = 32;
        for _ in 0..bl_hashes_len {
            block_locator_hashes.push(utils::clone_into_array(
                &crypto::bytes_to_hash32(&bytes[index..(index + next_size)]).unwrap(),
            ));
            index += next_size;
        }

        let hash_stop = utils::clone_into_array(
            &crypto::bytes_to_hash32(&bytes[index..(index + next_size)]).unwrap(),
        );

        MessageGetBlocks {
            version,
            block_locator_hashes,
            hash_stop,
        }
    }

    fn handle(&self, state: node::ConnectionState, _: net::TcpStream) -> node::ConnectionState {
        state
    }
}

impl MessageGetBlocks {
    ///
    /// block locator hashes should be provided in reverse order
    /// of block height.
    pub fn new(
        version: u32,
        block_locator_hashes: Vec<crypto::Hash32>,
        hash_stop: crypto::Hash32,
    ) -> Self {
        MessageGetBlocks {
            version,
            block_locator_hashes,
            hash_stop,
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::utils;

    #[test]
    fn test_message_get_blocks_empty() {
        let hash_babar = crypto::hash32("babar".as_bytes());
        let getblocks = MessageGetBlocks::new(0xea62, vec![], hash_babar);

        assert_eq!(getblocks.version, 0xea62);
        assert_eq!(
            getblocks.block_locator_hashes,
            vec![] as Vec<crypto::Hash32>
        );
        assert_eq!(getblocks.hash_stop, hash_babar);

        assert_eq!(
            getblocks.name(),
            [103 as u8, 101, 116, 98, 108, 111, 99, 107, 115, 0, 0, 0]
        );

        assert_eq!(getblocks.length(), 4 + 1 + 4);
        assert_eq!(
            hex::encode(getblocks.bytes()),
            "62ea00000040eb91391d1bd9c352902d9853eb5c3ca5dfab6000b3738d35fc0170a6aa4dc2"
        );
        assert_eq!(getblocks, MessageGetBlocks::from_bytes(&getblocks.bytes()));
    }

    #[test]
    fn test_message_get_blocks_bitcoin_org() {
        let getblocks = MessageGetBlocks::new(
            70001,
            vec![
                utils::clone_into_array(
                    hex::decode("00000000000000001bd3146aa1555e10b23b63e6d484987237b575778a609fd3")
                        .unwrap()
                        .as_slice(),
                ),
                utils::clone_into_array(
                    hex::decode("00000000000000000aea3be27cda4b71011c2b60fb8a2e0a113708d403643e5c")
                        .unwrap()
                        .as_slice(),
                ),
            ],
            utils::clone_into_array(
                hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
                    .unwrap()
                    .as_slice(),
            ),
        );

        assert_eq!(
            getblocks.name(),
            [103 as u8, 101, 116, 98, 108, 111, 99, 107, 115, 0, 0, 0]
        );

        assert_eq!(getblocks.length(), 4 + 1 + 4 * 2 + 4);
        assert_eq!(
            hex::encode(getblocks.bytes()),
            "7111010002d39f608a7775b537729884d4e6633bb2105e55a16a14d31b00000000000000005c\
             3e6403d40837110a2e8afb602b1c01714bda7ce23bea0a0000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000"
        );
        assert_eq!(getblocks, MessageGetBlocks::from_bytes(&getblocks.bytes()));
    }
}
