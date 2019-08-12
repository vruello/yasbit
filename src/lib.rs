extern crate hex;

mod block;
mod crypto;
mod merkle_tree;
mod message;
mod network;
mod script;
mod transaction;
mod utils;
mod variable_integer;

use std::time::SystemTime;

use crate::message::MessageCommand;
use block::Block;
use crypto::Hashable;
use std::net;
use transaction::Transaction;

pub fn run() {
    let mut tx = Transaction::new();
    // Coinbase generation input
    tx.add_input([0 as u8; 32], 0xffffffff, hex::decode("04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73").unwrap());
    // Output 50 BTC
    tx.add_output(5_000_000_000, hex::decode("4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac").unwrap());

    // Save tx hash
    let tx_hash = tx.hash();

    println!("Tx hash = {}", hex::encode(tx_hash));

    let mut block = Block::new(
        1,
        [0; 32], // Prev hash : 000..0 for the genesis block
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32,
        0,            // nonce
        1,            // difficulty
        Box::new(tx), // coinbase transaction
    );

    println!("{:?}", block);

    let mut tx = Transaction::new();
    tx.add_input(tx_hash, 0, b"TO SOMETHING".to_vec());
    // Output 0.5 BTC
    tx.add_output(50_000_000, b"TO A".to_vec());
    tx.add_output(50_000_000, b"TO B".to_vec());

    block.add_tx(Box::new(tx));

    println!("{:?}", block);

    println!("Version message");

    let node_addr: net::Ipv4Addr = "192.206.202.6".parse().unwrap();
    let my_addr: net::Ipv4Addr = "0.0.0.0".parse().unwrap();
    let message_version = message::version::MessageVersion::new(
        0xea62,
        message::NODE_NETWORK,
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u64,
        network::NetAddrVersion::new(message::NODE_NETWORK, node_addr.to_ipv6_mapped(), 0),
        network::NetAddrVersion::new(message::NODE_NETWORK, my_addr.to_ipv6_mapped(), 0),
        0x6517E68C5DB32E3B,
        "Babar".to_string(),
        0x033EC0,
    );

    let message = message::Message::new(message::MAGIC_MAIN, message_version);

    println!("Message: {}", hex::encode(message.bytes()));
}
