extern crate hex;

mod crypto;
mod transaction;
mod block;

use transaction::Transaction;
use block::Block;

pub fn run() {
    let mut tx = Transaction::new(1);
    // Coinbase generation input
    tx.add_input([0 as u8; 32], 0xffffffff, b"I can say whatever I want".to_vec());
    // Output 1 BTC
    tx.add_output(100_000_000, b"SOMETHING".to_vec());
    println!("{:?}", tx);
    
    println!("Bytes = {}", hex::encode(tx.bytes()));
    
    // Save tx hash
    let tx_hash = tx.hash();
    
    println!("Hash = {}", hex::encode(tx_hash));

    let mut block = Block::new(None, 4);
    block.add_tx(Box::new(tx));
    
    println!("{:?}", block);

    let mut tx = Transaction::new(1);
    tx.add_input(tx_hash, 0, b"TO SOMETHING".to_vec());
    // Output 0.5 BTC 
    tx.add_output(50_000_000, b"TO A".to_vec());
    tx.add_output(50_000_000, b"TO B".to_vec());

    println!("{:?}", tx);
    block.add_tx(Box::new(tx));

    println!("{:?}", block);
}
