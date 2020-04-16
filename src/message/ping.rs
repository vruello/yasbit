use crate::config;
use std::io::Write;

use crate::message;
use crate::message::MessageCommand;
use crate::node;
use crate::utils;

const NAME: &str = "ping";

#[derive(Debug, PartialEq)]
pub struct MessagePing {
    nonce: u64,
}

impl message::MessageCommand for MessagePing {
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
        MessagePing { nonce }
    }

    fn handle(&self, node: &mut node::Node, config: &config::Config) {
        let pong = message::pong::MessagePong::new(self.nonce);
        log::debug!("[{}] Sending pong message: {:?}", node.id(), pong);
        let message = message::Message::new(config.magic, pong);
        let stream = node.stream();
        stream.write(&message.bytes()).unwrap();
        stream.flush().unwrap();
    }
}

impl MessagePing {
    pub fn new(nonce: u64) -> Self {
        MessagePing { nonce }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_message_ping() {
        let ping = MessagePing::new(0xaabbccddeeff0011);

        assert_eq!(
            ping.name(),
            ['p' as u8, 'i' as u8, 'n' as u8, 'g' as u8, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(ping.length(), 8);
        assert_eq!(
            ping.bytes(),
            vec![0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa]
        );
        assert_eq!(ping, MessagePing::from_bytes(&ping.bytes()));
    }
}
