use crate::config;
use crate::message;
use crate::message::MessageCommand;
use crate::node;
use crate::utils;

const NAME: &str = "pong";

#[derive(Debug, PartialEq, Clone)]
pub struct MessagePong {
    nonce: u64,
}

impl message::MessageCommand for MessagePong {
    fn name(&self) -> [u8; 12] {
        let mut command = [0; 12];
        for (i, c) in NAME.char_indices() {
            command[i] = c as u8;
        }
        command
    }

    fn length(&self) -> u32 {
        8u32
    }

    fn bytes(&self) -> Vec<u8> {
        self.nonce.to_le_bytes().to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), 8);
        let nonce = u64::from_le_bytes(utils::clone_into_array(&bytes));
        MessagePong { nonce }
    }

    fn handle(&self, node: &mut node::Node, config: &config::Config) {}
}

impl MessagePong {
    pub fn new(nonce: u64) -> Self {
        MessagePong { nonce }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_message_pong() {
        let pong = MessagePong::new(0xaabbccddeeff0011);

        assert_eq!(
            pong.name(),
            ['p' as u8, 'o' as u8, 'n' as u8, 'g' as u8, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(pong.length(), 8);
        assert_eq!(
            pong.bytes(),
            vec![0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa]
        );
        assert_eq!(pong, MessagePong::from_bytes(&pong.bytes()));
    }
}
