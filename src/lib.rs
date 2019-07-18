extern crate hex;

mod crypto;
mod transaction;
mod block;
mod variable_integer;
mod merkle_tree;
mod script;
mod network;
mod message;

use std::time::SystemTime;

use transaction::Transaction;
use block::Block;
use crypto::{Hashable};

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
        SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as u32,
        0, // nonce
        1, // difficulty
        Box::new(tx) // coinbase transaction
    );
    
    println!("{:?}", block);

    let mut tx = Transaction::new();
    tx.add_input(tx_hash, 0, b"TO SOMETHING".to_vec());
    // Output 0.5 BTC 
    tx.add_output(50_000_000, b"TO A".to_vec());
    tx.add_output(50_000_000, b"TO B".to_vec());

    block.add_tx(Box::new(tx));

    println!("{:?}", block);
}
