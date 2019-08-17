extern crate hex;

use std::sync::mpsc;

use crate::crypto;
use crate::message;
use crate::message::inv_base::*;
use crate::message::MessageCommand;
use crate::utils;
use crate::variable_integer::VariableInteger;

const NAME: &str = "notfound";

#[derive(Debug, PartialEq)]
pub struct MessageNotFound {
    base: MessageInvBase,
}

impl message::MessageCommand for MessageNotFound {
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
        MessageNotFound {
            base: MessageInvBase::from_bytes(&bytes),
        }
    }

    fn handle(&self, t_cw: &mpsc::Sender<Vec<u8>>) {
        for inv_vect in self.base.inventory.iter() {
            println!(
                "{} {}",
                hash_type_to_str(inv_vect.hash_type),
                hex::encode(inv_vect.hash)
            );
        }
    }
}

impl MessageNotFound {
    pub fn new(inventory: Vec<InvVect>) -> Self {
        MessageNotFound {
            base: MessageInvBase { inventory },
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_message_notfound() {
        let notfound = MessageNotFound::new(vec![
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
            notfound.name(),
            [
                'n' as u8, 'o' as u8, 't' as u8, 'f' as u8, 'o' as u8, 'u' as u8, 'n' as u8,
                'd' as u8, 0, 0, 0, 0
            ]
        );
        assert_eq!(notfound.length() as usize, 1 + 2 * 36);
        assert_eq!(notfound.length() as usize, notfound.bytes().len());
        assert_eq!(notfound, MessageNotFound::from_bytes(&notfound.bytes()));
    }
}
