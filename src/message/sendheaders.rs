use std::net;

use crate::message;
use crate::message::MessageCommand;
use crate::node;

const NAME: &str = "sendheaders";

#[derive(PartialEq, Debug)]
pub struct MessageSendHeaders {}

impl message::MessageCommand for MessageSendHeaders {
    fn name(&self) -> [u8; 12] {
        let mut command = [0; 12];
        for (i, c) in NAME.char_indices() {
            command[i] = c as u8;
        }
        command
    }

    fn length(&self) -> u32 {
        0
    }

    fn bytes(&self) -> Vec<u8> {
        Vec::new()
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        assert!(bytes.is_empty());
        MessageSendHeaders {}
    }

    fn handle(&self, state: node::ConnectionState, _: net::TcpStream) -> node::ConnectionState {
        state
    }
}

impl MessageSendHeaders {
    pub fn new() -> Self {
        MessageSendHeaders {}
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_message_sendheaders() {
        let sendheaders = MessageSendHeaders::new();
        assert_eq!(
            sendheaders.name(),
            [
                's' as u8, 'e' as u8, 'n' as u8, 'd' as u8, 'h' as u8, 'e' as u8, 'a' as u8,
                'd' as u8, 'e' as u8, 'r' as u8, 's' as u8, 0
            ]
        );
        assert_eq!(sendheaders.length(), 0);
        assert_eq!(sendheaders.bytes().len(), 0);
        assert_eq!(
            sendheaders,
            MessageSendHeaders::from_bytes(&sendheaders.bytes())
        );
    }

    #[test]
    #[should_panic]
    fn test_message_sendheaders_panic() {
        let sendheaders = MessageSendHeaders::from_bytes(&vec![1]);
    }
}
