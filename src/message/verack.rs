use std::sync::mpsc;

use crate::message;
use crate::message::MessageCommand;

const NAME: &str = "verack";

#[derive(PartialEq, Debug)]
pub struct MessageVerack {}

impl message::MessageCommand for MessageVerack {
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
        MessageVerack {}
    }

    fn handle(&self, t_cw: &mpsc::Sender<Vec<u8>>) {}
}

impl MessageVerack {
    pub fn new() -> Self {
        MessageVerack {}
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_message_verack() {
        let verack = MessageVerack::new();
        assert_eq!(
            verack.name(),
            ['v' as u8, 'e' as u8, 'r' as u8, 'a' as u8, 'c' as u8, 'k' as u8, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(verack.length(), 0);
        assert_eq!(verack.bytes().len(), 0);

        let new_verack = MessageVerack::from_bytes(&vec![]);
        assert_eq!(verack, new_verack);
    }

    #[test]
    #[should_panic]
    fn test_message_verack_panic() {
        let verack = MessageVerack::from_bytes(&vec![1]);
    }
}
