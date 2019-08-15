extern crate hex;

use std::sync::mpsc;

use crate::crypto;
use crate::message;
use crate::message::MessageCommand;
use crate::utils;
use crate::variable_integer::VariableInteger;

const NAME: &str = "inv";

const ERROR: u32 = 0;
const MSG_TX: u32 = 1;
const MSG_BLOCK: u32 = 2;
const MSG_FILTERED_BLOCK: u32 = 3;
const MSG_CMPCT_BLOCK: u32 = 4;

#[derive(Debug, PartialEq)]
pub struct InvVect {
    hash_type: u32,
    hash: crypto::Hash32,
}

fn hash_type_is_valid(hash_type: u32) -> bool {
    hash_type >= 0 && hash_type <= 4
}

fn hash_type_to_str(hash_type: u32) -> &'static str {
    match hash_type {
        ERROR => "ERROR",
        MSG_TX => "MSG_TX",
        MSG_BLOCK => "MSG_BLOCK",
        MSG_FILTERED_BLOCK => "MSG_FILTERED_BLOCK",
        MSG_CMPCT_BLOCK => "MSG_CMPCT_BLOCK",
        _ => "UNKNOWN",
    }
}

#[derive(Debug, PartialEq)]
pub struct MessageInv {
    inventory: Vec<InvVect>,
}

impl message::MessageCommand for MessageInv {
    fn name(&self) -> [u8; 12] {
        let mut command = [0; 12];
        for (i, c) in NAME.char_indices() {
            command[i] = c as u8;
        }
        command
    }

    fn length(&self) -> u32 {
        let inventory_len_size = VariableInteger::new(self.inventory.len() as u64)
            .bytes()
            .len();
        (inventory_len_size + self.inventory.len() * (4 + 32)) as u32
    }

    fn bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        let inventory_len = VariableInteger::new(self.inventory.len() as u64);
        bytes.extend_from_slice(&inventory_len.bytes());

        for inv_vect in self.inventory.iter() {
            bytes.extend_from_slice(&inv_vect.hash_type.to_le_bytes());
            bytes.extend_from_slice(&crypto::hash32_to_bytes(&inv_vect.hash));
        }

        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        let mut index = 0;

        let (inventory_len, inventory_len_size) = VariableInteger::from_bytes(&bytes).unwrap();
        index += inventory_len_size;

        let mut inventory = Vec::with_capacity(inventory_len as usize);
        let mut next_size = 4;
        for _ in 0..inventory_len {
            next_size = 4;
            let hash_type =
                u32::from_le_bytes(utils::clone_into_array(&bytes[index..(index + next_size)]));
            assert!(hash_type_is_valid(hash_type));
            index += next_size;

            next_size = 32;
            let hash = utils::clone_into_array(
                &crypto::bytes_to_hash32(&bytes[index..(index + next_size)]).unwrap(),
            );
            index += next_size;

            inventory.push(InvVect { hash_type, hash })
        }

        MessageInv { inventory }
    }

    fn handle(&self, t_cw: &mpsc::Sender<Vec<u8>>) {
        for inv_vect in self.inventory.iter() {
            println!(
                "{} {}",
                hash_type_to_str(inv_vect.hash_type),
                hex::encode(inv_vect.hash)
            );
        }
    }
}

impl MessageInv {
    pub fn new(inventory: Vec<InvVect>) -> Self {
        MessageInv { inventory }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_message_inv() {
        let inc = MessageInv::new(vec![
            InvVect {
                hash_type: MSG_TX,
                hash: crypto::hash32("babar".as_bytes()),
            },
            InvVect {
                hash_type: MSG_BLOCK,
                hash: crypto::hash32("toto".as_bytes()),
            },
        ]);

        assert_eq!(
            inc.name(),
            ['i' as u8, 'n' as u8, 'v' as u8, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(inc.length() as usize, 1 + 2 * 36);
        assert_eq!(inc.length() as usize, inc.bytes().len());
        assert_eq!(inc, MessageInv::from_bytes(&inc.bytes()));
    }
}
