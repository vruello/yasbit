use crate::message;
use crate::message::MessageCommand;

const NAME: &str = "getaddr";

pub struct MessageGetAddr {
    // No payload
}

impl message::MessageCommand for MessageGetAddr {
    fn name(&self) -> [u8;12] {
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
}

impl MessageGetAddr {
    fn new() -> Self {
        MessageGetAddr { }
    }
}

#[cfg(test)]
mod tests {
    
    use super::*;

    #[test]
    fn test_message_get_addr() {
        let message_get_addr = MessageGetAddr::new();
        assert_eq!(message_get_addr.name(),
                   [103 as u8, 101, 116, 97, 100, 100, 114, 0, 0, 0, 0, 0]);
        assert_eq!(message_get_addr.length(), 0);
        assert_eq!(message_get_addr.bytes(), vec![]);

    }
}