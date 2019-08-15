use std::sync::mpsc;

use crate::crypto;
use crate::message;
use crate::message::MessageCommand;
use crate::utils;
use crate::variable_integer::VariableInteger;

const NAME: &str = "getheaders";

#[derive(PartialEq, Debug)]
pub struct MessageGetHeaders {
    version: u32,
    block_locator_hashes: Vec<crypto::Hash32>,
    hash_stop: crypto::Hash32,
}

impl message::MessageCommand for MessageGetHeaders {
    fn name(&self) -> [u8; 12] {
        let mut command = [0; 12];
        for (i, c) in NAME.char_indices() {
            command[i] = c as u8;
        }
        command
    }

    fn length(&self) -> u32 {
        let bl_hashes_len_size = VariableInteger::new(self.block_locator_hashes.len() as u64)
            .bytes()
            .len();
        (4 + bl_hashes_len_size + 32 * self.block_locator_hashes.len() + 32) as u32
    }

    fn bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.version.to_le_bytes());

        let bl_hashes_len = VariableInteger::new(self.block_locator_hashes.len() as u64);
        bytes.extend_from_slice(bl_hashes_len.bytes().as_slice());

        for hash in self.block_locator_hashes.iter() {
            bytes.extend_from_slice(hash);
        }

        bytes.extend_from_slice(&self.hash_stop);
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
            block_locator_hashes.push(utils::clone_into_array(&bytes[index..(index + next_size)]));
            index += next_size;
        }

        let hash_stop = utils::clone_into_array(&bytes[index..(index + next_size)]);

        MessageGetHeaders {
            version,
            block_locator_hashes,
            hash_stop,
        }
    }

    fn handle(&self, t_cw: &mpsc::Sender<Vec<u8>>) {}
}

impl MessageGetHeaders {
    pub fn new(
        version: u32,
        block_locator_hashes: Vec<crypto::Hash32>,
        hash_stop: crypto::Hash32,
    ) -> Self {
        MessageGetHeaders {
            version,
            block_locator_hashes,
            hash_stop,
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_message_getheaders() {
        let getheaders = MessageGetHeaders::new(
            1,
            vec![
                crypto::hash32("babar".as_bytes()),
                crypto::hash32("toto".as_bytes()),
            ],
            crypto::hash32("tata".as_bytes()),
        );

        assert_eq!(
            getheaders.name(),
            [
                'g' as u8, 'e' as u8, 't' as u8, 'h' as u8, 'e' as u8, 'a' as u8, 'd' as u8,
                'e' as u8, 'r' as u8, 's' as u8, 0, 0
            ]
        );
        assert_eq!(getheaders.length() as usize, 4 + 1 + 32 * 2 + 32);
        assert_eq!(getheaders.length() as usize, getheaders.bytes().len());
        assert_eq!(
            getheaders,
            MessageGetHeaders::from_bytes(&getheaders.bytes())
        );
    }
}
