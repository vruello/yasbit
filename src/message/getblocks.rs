use std::sync::mpsc;

use crate::crypto;
use crate::message;
use crate::message::MessageCommand;
use crate::variable_integer::VariableInteger;

const NAME: &str = "getblocks";

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
            bytes.extend_from_slice(hash);
        }

        bytes.extend_from_slice(&self.hash_stop);

        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        // TODO
        MessageGetBlocks {
            version: 4,
            block_locator_hashes: Vec::new(),
            hash_stop: crypto::hash32("babar".as_bytes()),
        }
    }

    fn handle(&self, t_cw: &mpsc::Sender<Vec<u8>>) {}
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
            "62ea000000c24daaa67001fc358d73b30060abdfa53c5ceb53982d9052c3d91b1d3991eb40"
        );
    }

    #[test]
    fn test_message_get_blocks_bitcoin_org() {
        let getblocks = MessageGetBlocks::new(
            70001,
            vec![
                utils::clone_into_array(
                    hex::decode("d39f608a7775b537729884d4e6633bb2105e55a16a14d31b0000000000000000")
                        .unwrap()
                        .as_slice(),
                ),
                utils::clone_into_array(
                    hex::decode("5c3e6403d40837110a2e8afb602b1c01714bda7ce23bea0a0000000000000000")
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
    }
}
