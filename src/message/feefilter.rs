use std::net;

use crate::message;
use crate::message::MessageCommand;
use crate::node;
use crate::utils;

const NAME: &str = "feefilter";

#[derive(Debug, PartialEq)]
pub struct MessageFeeFilter {
    feerate: u64,
}

impl message::MessageCommand for MessageFeeFilter {
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
        self.feerate.to_le_bytes().to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), 8);
        let feerate = u64::from_le_bytes(utils::clone_into_array(&bytes));
        MessageFeeFilter { feerate }
    }

    fn handle(&self, state: node::ConnectionState, _: net::TcpStream) -> node::ConnectionState {
        state
    }
}

impl MessageFeeFilter {
    pub fn new(feerate: u64) -> Self {
        MessageFeeFilter { feerate }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_message_feefilter() {
        let feefilter = MessageFeeFilter::new(0xaabbccddeeff0011);
        assert_eq!(
            feefilter.name(),
            [
                'f' as u8, 'e' as u8, 'e' as u8, 'f' as u8, 'i' as u8, 'l' as u8, 't' as u8,
                'e' as u8, 'r' as u8, 0, 0, 0
            ]
        );
        assert_eq!(feefilter.length() as usize, 8);
        assert_eq!(feefilter.length() as usize, feefilter.bytes().len());
        assert_eq!(feefilter, MessageFeeFilter::from_bytes(&feefilter.bytes()));
    }
}
