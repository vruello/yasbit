use crate::config;
extern crate hex;

use crate::crypto;
use crate::message;
use crate::message::inv_base::*;
use crate::message::MessageCommand;
use crate::node;
use crate::utils;
use crate::variable_integer::VariableInteger;

const NAME: &str = "getdata";

#[derive(Debug, PartialEq, Clone)]
pub struct MessageGetData {
    base: MessageInvBase,
}

impl message::MessageCommand for MessageGetData {
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
        MessageGetData {
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

impl MessageGetData {
    pub fn new(inventory: Vec<InvVect>) -> Self {
        MessageGetData {
            base: MessageInvBase { inventory },
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_message_getdata() {
        let getdata = MessageGetData::new(vec![
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
            getdata.name(),
            [
                'g' as u8, 'e' as u8, 't' as u8, 'd' as u8, 'a' as u8, 't' as u8, 'a' as u8, 0, 0,
                0, 0, 0
            ]
        );
        assert_eq!(getdata.length() as usize, 1 + 2 * 36);
        assert_eq!(getdata.length() as usize, getdata.bytes().len());
        assert_eq!(getdata, MessageGetData::from_bytes(&getdata.bytes()));
    }
}
