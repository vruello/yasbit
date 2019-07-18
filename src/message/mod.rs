use crate::network;
use crate::crypto;

pub mod version;

const MAGIC_MAIN: u32 = 0xD9B4BEF9;
const MAGIC_TESTNET: u32 = 0xDAB5BFFA;
const MAGIC_TESTNET3: u32 = 0x0709110B;
const MAGIC_NAMECOIN: u32 = 0xFEB4BEF9;

pub const NODE_NETWORK: u64 = 1;
pub const NODE_GETUTXO: u64 = 2;
pub const NODE_BLOOM: u64 = 4;
pub const NODE_WITNESS: u64 = 8;
pub const NODE_NETWORK_LIMITED: u64 = 1024;

pub trait MessageCommand {
    fn bytes(&self) -> Vec<u8>;
    fn length(&self) -> u32;
    fn name(&self) -> [u8; 12];
}

pub struct Message<T: MessageCommand> {
    magic: u32, // Magic value indicating message origin network, and used to
                // seek to next message when stream state is unknown
    command: T
}

impl<T> Message<T> where T: MessageCommand {
    fn new(magic: u32, command: T) -> Self {
        Message {
            magic,
            command
        }
    }

    fn bytes(&self) -> Vec<u8> {
        let command_bytes = self.command.bytes();
        let checksum = &crypto::hash32(&command_bytes.as_slice())[0..4];
        let command_length = self.command.length();

        // Compute total length to improve performances
        // magic + command + length + checksum + payload.length()
        let length = 4 + 12 + 4 + 4 + command_length;
        let mut bytes = Vec::with_capacity(length as usize);

        // Magic value indicating message origin network
        bytes.extend_from_slice(&self.magic.to_le_bytes());
        // ASCII string identifying the packet content, NULL padded
        bytes.extend_from_slice(&self.command.name());
        // Length of payload in number of bytes
        bytes.extend_from_slice(&command_length.to_le_bytes());
        // First 4 bytes of sha256(sha256(payload))
        bytes.extend_from_slice(checksum);
        // The actual data
        bytes.extend_from_slice(&command_bytes.as_slice());
        bytes
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    struct MessageMock {
        name: [u8; 12],
        payload: Vec<u8>
    }

    impl MessageCommand for MessageMock {
        fn name(&self) -> [u8; 12] {
            self.name
        }

        fn length(&self) -> u32 {
            self.payload.len() as u32
        }

        fn bytes(&self) -> Vec<u8> {
            self.payload.clone()
        }
    }

    impl MessageMock {
        fn new(name: [u8; 12], payload: Vec<u8>) -> Self {
            MessageMock {
                name,
                payload
            }
        }
    }

    #[test]
    fn test_message() {
        let name = ['v' as u8, 'e' as u8, 'r' as u8, 's' as u8,
                   'i' as u8, 'o' as u8, 'n' as u8, 0, 0, 0, 0, 0];
        let payload_hex = "62ea0000010000000000000011b2d0500000000001000000000\
                           0000000000000000000000000ffff0000000000000000000000\
                           00000000000000000000000000ffff0000000000003b2eb35d8\
                           ce617650f2f5361746f7368693a302e372e322fc03e0300";
        let payload = hex::decode(&payload_hex).unwrap();
        let mock = MessageMock::new(name, payload.clone());

        assert_eq!(mock.name(), name);
        assert_eq!(mock.length(), 100);
        assert_eq!(payload_hex, hex::encode(mock.bytes()));


        let message = Message::new(MAGIC_MAIN, mock);

        assert_eq!(message.magic, 0xd9b4bef9);
        assert_eq!(
            "f9beb4d976657273696f6e000000000064000000358d493262ea0000010000000\
            000000011b2d05000000000010000000000000000000000000000000000ffff000\
            000000000000000000000000000000000000000000000ffff0000000000003b2eb\
            35d8ce617650f2f5361746f7368693a302e372e322fc03e0300",
            hex::encode(message.bytes()));

    }
}
