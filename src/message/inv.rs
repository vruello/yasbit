use crate::config;
extern crate hex;

use crate::crypto;
use crate::message;
use crate::message::inv_base::*;
use crate::message::MessageCommand;
use crate::node;
use crate::utils;
use crate::variable_integer::VariableInteger;

const NAME: &str = "inv";

#[derive(Debug, PartialEq, Clone)]
pub struct MessageInv {
    base: MessageInvBase,
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
        self.base.length()
    }

    fn bytes(&self) -> Vec<u8> {
        self.base.bytes()
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        MessageInv {
            base: MessageInvBase::from_bytes(&bytes),
        }
    }

    fn handle(&self, node: &mut node::Node, config: &config::Config) {
        for inv_vect in self.base.inventory.iter() {
            log::trace!(
                "{} {}",
                hash_type_to_str(inv_vect.hash_type),
                hex::encode(inv_vect.hash)
            );
        }
    }
}

impl MessageInv {
    pub fn new(inventory: Vec<InvVect>) -> Self {
        MessageInv {
            base: MessageInvBase { inventory },
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_message_inv() {
        let inv = MessageInv::new(vec![
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
            inv.name(),
            ['i' as u8, 'n' as u8, 'v' as u8, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(inv.length() as usize, 1 + 2 * 36);
        assert_eq!(inv.length() as usize, inv.bytes().len());
        assert_eq!(inv, MessageInv::from_bytes(&inv.bytes()));
    }
}
