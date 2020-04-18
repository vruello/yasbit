use crate::block;
use crate::config;
use crate::crypto::Hashable;
use crate::message;
use crate::message::MessageCommand;
use crate::node;
use std::convert::TryInto;

const NAME: &str = "block";

#[derive(Debug, PartialEq, Clone)]
pub struct MessageBlock {
    block: block::Block,
}

impl message::MessageCommand for MessageBlock {
    fn name(&self) -> [u8; 12] {
        let mut command = [0; 12];
        for (i, c) in NAME.char_indices() {
            command[i] = c as u8;
        }
        command
    }

    fn length(&self) -> u32 {
        self.bytes().len().try_into().unwrap()
    }

    fn bytes(&self) -> Vec<u8> {
        self.block.bytes()
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        MessageBlock {
            block: block::Block::from_bytes(bytes),
        }
    }

    fn handle(&self, node: &mut node::Node, config: &config::Config) {
        log::debug!("[{:?}] Received block {:?}", node.id(), self.block.hash());
        node.send_response(node::NodeResponseContent::Block(self.block.clone()))
            .unwrap();
    }
}

impl MessageBlock {
    pub fn new(block: block::Block) -> Self {
        MessageBlock { block }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_block() {
        let config = config::main_config();
        let block = config.genesis_block;
        let message_block = MessageBlock::new(block.clone());

        assert_eq!(
            message_block.name(),
            ['b' as u8, 'l' as u8, 'o' as u8, 'c' as u8, 'k' as u8, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(message_block.length() as usize, block.bytes().len());
        assert_eq!(
            message_block,
            MessageBlock::from_bytes(&message_block.bytes())
        );
    }
}
