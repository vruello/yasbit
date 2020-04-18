use crate::config;
use crate::crypto;
use crate::node;
use crate::utils;

pub mod addr;
pub mod alert;
pub mod block;
pub mod feefilter;
pub mod getaddr;
pub mod getblocks;
pub mod getdata;
pub mod getheaders;
pub mod headers;
pub mod inv;
pub mod inv_base;
pub mod notfound;
pub mod ping;
pub mod pong;
pub mod sendheaders;
pub mod verack;
pub mod version;

pub const MAGIC_MAIN: u32 = 0xD9B4BEF9;
pub const MAGIC_TESTNET: u32 = 0xDAB5BFFA;
pub const MAGIC_TESTNET3: u32 = 0x0709110B;
pub const MAGIC_NAMECOIN: u32 = 0xFEB4BEF9;

pub const NODE_NETWORK: u64 = 1;
pub const NODE_GETUTXO: u64 = 2;
pub const NODE_BLOOM: u64 = 4;
pub const NODE_WITNESS: u64 = 8;
pub const NODE_NETWORK_LIMITED: u64 = 1024;

#[derive(Debug, Clone)]
pub enum MessageType {
    Version(Message<version::MessageVersion>),
    Alert(Message<alert::MessageAlert>),
    Verack(Message<verack::MessageVerack>),
    Addr(Message<addr::MessageAddr>),
    GetAddr(Message<getaddr::MessageGetAddr>),
    Ping(Message<ping::MessagePing>),
    Pong(Message<pong::MessagePong>),
    GetHeaders(Message<getheaders::MessageGetHeaders>),
    FeeFilter(Message<feefilter::MessageFeeFilter>),
    SendHeaders(Message<sendheaders::MessageSendHeaders>),
    Inv(Message<inv::MessageInv>),
    GetData(Message<getdata::MessageGetData>),
    GetBlocks(Message<getblocks::MessageGetBlocks>),
    NotFound(Message<notfound::MessageNotFound>),
    Headers(Message<headers::MessageHeaders>),
    Block(Message<block::MessageBlock>),
}

impl MessageType {
    pub fn bytes(self) -> Vec<u8> {
        match self {
            MessageType::Version(message) => message.bytes(),
            MessageType::Alert(message) => message.bytes(),
            MessageType::Verack(message) => message.bytes(),
            MessageType::Addr(message) => message.bytes(),
            MessageType::GetAddr(message) => message.bytes(),
            MessageType::Ping(message) => message.bytes(),
            MessageType::Pong(message) => message.bytes(),
            MessageType::GetHeaders(message) => message.bytes(),
            MessageType::FeeFilter(message) => message.bytes(),
            MessageType::SendHeaders(message) => message.bytes(),
            MessageType::Inv(message) => message.bytes(),
            MessageType::GetData(message) => message.bytes(),
            MessageType::GetBlocks(message) => message.bytes(),
            MessageType::NotFound(message) => message.bytes(),
            MessageType::Headers(message) => message.bytes(),
            MessageType::Block(message) => message.bytes(),
        }
    }
}

pub trait MessageCommand {
    fn bytes(&self) -> Vec<u8>;
    fn from_bytes(_: &[u8]) -> Self;
    fn length(&self) -> u32;
    fn name(&self) -> [u8; 12];
    fn handle(&self, node: &mut node::Node, config: &config::Config);
}

#[derive(Debug, PartialEq, Clone)]
pub struct Message<T: MessageCommand> {
    magic: u32, // Magic value indicating message origin network, and used to
    // seek to next message when stream state is unknown
    pub command: T,
}

impl<T> Message<T>
where
    T: MessageCommand,
{
    pub fn new(magic: u32, command: T) -> Self {
        Message { magic, command }
    }

    pub fn bytes(&self) -> Vec<u8> {
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

#[derive(Debug)]
pub enum ParseError {
    InvalidMagicBytes,
    InvalidChecksum,
    UnknownMessage(String),
    Partial(usize),
}

fn check_size(bytes: &[u8], length: usize) -> bool {
    bytes.len() >= length
}

pub fn parse(bytes: &[u8]) -> Result<(MessageType, usize), ParseError> {
    let mut to_read = 24;
    let mut index = 0;

    let mut next_size = 4;
    if !check_size(bytes, index + next_size) {
        return Err(ParseError::Partial(to_read - bytes.len()));
    }
    let magic = u32::from_le_bytes(utils::clone_into_array(&bytes[index..(index + next_size)]));
    index += next_size;

    // Check magic
    if !(magic == MAGIC_MAIN || magic == MAGIC_TESTNET || magic == MAGIC_TESTNET3) {
        return Err(ParseError::InvalidMagicBytes);
    }

    next_size = 12;
    if !check_size(bytes, index + next_size) {
        return Err(ParseError::Partial(to_read - bytes.len()));
    }
    let mut first_zero = 0;
    for i in 0..next_size {
        if bytes[index + i] == 0 {
            first_zero = i;
            break;
        }
    }
    let name = std::str::from_utf8(&bytes[index..(index + first_zero)])
        .unwrap()
        .to_owned();
    index += next_size;

    next_size = 4;
    if !check_size(bytes, index + next_size) {
        return Err(ParseError::Partial(to_read - bytes.len()));
    }
    let length = u32::from_le_bytes(utils::clone_into_array(&bytes[index..(index + next_size)]));
    index += next_size;

    // Now we know how many bytes have to be read
    to_read += length as usize;

    next_size = 4;
    if !check_size(bytes, index + next_size) {
        return Err(ParseError::Partial(to_read - bytes.len()));
    }
    let checksum = &bytes[index..(index + next_size)];
    index += next_size;

    next_size = length as usize;
    if !check_size(bytes, index + next_size) {
        return Err(ParseError::Partial(to_read - bytes.len()));
    }
    let payload = &bytes[index..(index + length as usize)];

    // Check checksum
    if &crypto::hash32(payload)[0..4] != checksum {
        return Err(ParseError::InvalidChecksum);
    }

    log::trace!("payload: {:?}", payload);
    let message;
    if name == "version" {
        let command = version::MessageVersion::from_bytes(&payload);
        message = MessageType::Version(Message { magic, command });
    } else if name == "alert" {
        let command = alert::MessageAlert::from_bytes(&payload);
        message = MessageType::Alert(Message { magic, command });
    } else if name == "verack" {
        let command = verack::MessageVerack::from_bytes(&payload);
        message = MessageType::Verack(Message { magic, command });
    } else if name == "getaddr" {
        let command = getaddr::MessageGetAddr::from_bytes(&payload);
        message = MessageType::GetAddr(Message { magic, command });
    } else if name == "addr" {
        let command = addr::MessageAddr::from_bytes(&payload);
        message = MessageType::Addr(Message { magic, command });
    } else if name == "ping" {
        let command = ping::MessagePing::from_bytes(&payload);
        message = MessageType::Ping(Message { magic, command });
    } else if name == "pong" {
        let command = pong::MessagePong::from_bytes(&payload);
        message = MessageType::Pong(Message { magic, command });
    } else if name == "getheaders" {
        let command = getheaders::MessageGetHeaders::from_bytes(&payload);
        message = MessageType::GetHeaders(Message { magic, command });
    } else if name == "feefilter" {
        let command = feefilter::MessageFeeFilter::from_bytes(&payload);
        message = MessageType::FeeFilter(Message { magic, command });
    } else if name == "sendheaders" {
        let command = sendheaders::MessageSendHeaders::from_bytes(&payload);
        message = MessageType::SendHeaders(Message { magic, command });
    } else if name == "inv" {
        let command = inv::MessageInv::from_bytes(&payload);
        message = MessageType::Inv(Message { magic, command });
    } else if name == "getblocks" {
        let command = getblocks::MessageGetBlocks::from_bytes(&payload);
        message = MessageType::GetBlocks(Message { magic, command });
    } else if name == "getdata" {
        let command = getdata::MessageGetData::from_bytes(&payload);
        message = MessageType::GetData(Message { magic, command });
    } else if name == "notfound" {
        let command = notfound::MessageNotFound::from_bytes(&payload);
        message = MessageType::NotFound(Message { magic, command });
    } else if name == "headers" {
        let command = headers::MessageHeaders::from_bytes(&payload);
        message = MessageType::Headers(Message { magic, command });
    } else if name == "block" {
        let command = block::MessageBlock::from_bytes(&payload);
        message = MessageType::Block(Message { magic, command });
    } else {
        return Err(ParseError::UnknownMessage(name.clone()));
    }

    Ok((message, 24 + length as usize))
}

#[cfg(test)]
mod tests {

    use super::*;

    struct MessageMock {
        name: [u8; 12],
        payload: Vec<u8>,
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

        fn from_bytes(bytes: &[u8]) -> Self {
            let name = [
                'm' as u8, 'o' as u8, 'c' as u8, 'k' as u8, 0, 0, 0, 0, 0, 0, 0, 0,
            ];
            MessageMock {
                name,
                payload: bytes.to_vec(),
            }
        }

        fn handle(&self, node: &mut node::Node, config: &config::Config) {}
    }

    impl MessageMock {
        fn new(name: [u8; 12], payload: Vec<u8>) -> Self {
            MessageMock { name, payload }
        }
    }

    #[test]
    fn test_version_message() {
        let name = [
            'v' as u8, 'e' as u8, 'r' as u8, 's' as u8, 'i' as u8, 'o' as u8, 'n' as u8, 0, 0, 0,
            0, 0,
        ];
        let payload_hex = "62ea0000010000000000000011b2d0500000000001000000000\
                           0000000000000000000000000ffff0000000000000000000000\
                           00000000000000000000000000ffff0000000000003b2eb35d8\
                           ce617650f2f5361746f7368693a302e372e322fc03e030001";
        let payload = hex::decode(&payload_hex).unwrap();
        let mock = MessageMock::new(name, payload.clone());

        assert_eq!(mock.name(), name);
        assert_eq!(mock.length(), 101);
        assert_eq!(payload_hex, hex::encode(mock.bytes()));

        let message = Message::new(MAGIC_MAIN, mock);

        assert_eq!(message.magic, MAGIC_MAIN);
        assert_eq!(
            "f9beb4d976657273696f6e000000000065000000c5d995ec62ea0000010000000\
             000000011b2d05000000000010000000000000000000000000000000000ffff000\
             000000000000000000000000000000000000000000000ffff0000000000003b2eb\
             35d8ce617650f2f5361746f7368693a302e372e322fc03e030001",
            hex::encode(message.bytes())
        );

        let bytes = message.bytes();
        let (parsed_message, length) = parse(&bytes).unwrap();

        if let MessageType::Version(version) = parsed_message {
            assert_eq!(bytes, version.bytes());
        }
        assert_eq!(length, 125);

        let mut inv_checksum_bytes = bytes.clone();
        inv_checksum_bytes[35] = inv_checksum_bytes[35] + 1;
        match parse(&inv_checksum_bytes) {
            Err(ParseError::InvalidChecksum) => assert!(true),
            _ => assert!(false),
        }

        let mut inv_magic_bytes = bytes.clone();
        inv_magic_bytes[0] = inv_magic_bytes[0] + 1;
        match parse(&inv_magic_bytes) {
            Err(ParseError::InvalidMagicBytes) => assert!(true),
            _ => assert!(false),
        }

        match parse(&bytes[..5]) {
            Err(ParseError::Partial(nb)) => assert_eq!(nb, 19),
            _ => assert!(false),
        }

        match parse(&bytes[..19]) {
            Err(ParseError::Partial(nb)) => assert_eq!(nb, 5),
            _ => assert!(false),
        }

        match parse(&bytes[..20]) {
            Err(ParseError::Partial(nb)) => assert_eq!(nb, 105),
            _ => assert!(false),
        }

        match parse(&bytes[..24]) {
            Err(ParseError::Partial(nb)) => assert_eq!(nb, 101),
            _ => assert!(false),
        }

        match parse(&bytes[..122]) {
            Err(ParseError::Partial(nb)) => assert_eq!(nb, 3),
            _ => assert!(false),
        }
    }
}
