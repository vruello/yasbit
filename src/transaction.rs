extern crate hex;

use crate::crypto::{hash32, Hash32};
use crate::variable_integer::VariableInteger;


/// A transaction is represented here
/// See https://en.bitcoin.it/wiki/Transactions
// FIXME Support flag and witnesses
#[derive(Debug)]
pub struct Transaction {
    version: u32,
    inputs: Vec<Box<TxInput>>,
    outputs: Vec<Box<TxOutput>>,
    lock_time: u32
}

#[derive(Debug)]
struct TxInput {
    tx: Hash32,
    index: u32,
    script_sig: Vec<u8>,
    sequence: u32,
}

impl TxInput {
    fn bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.tx);

        bytes.extend_from_slice(&self.index.to_le_bytes());
        bytes.extend_from_slice(&self.script_sig.as_slice());
        bytes.extend_from_slice(&self.sequence.to_le_bytes());
        bytes
    }
}

#[derive(Debug)]
struct TxOutput {
    value: u64,
    script_pub_key: Vec<u8>
}

impl TxOutput {
    fn bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.value.to_le_bytes());
        bytes.extend_from_slice(self.script_pub_key.as_slice());
        bytes
    }
}

impl Transaction {

    /// Creates a new transaction
    pub fn new() -> Self {
        Transaction {
            version: 1, 
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0
        }
    }

    /// Adds an input to the transaction
    pub fn add_input(&mut self, tx: Hash32, index: u32, script_sig: Vec<u8>) {
        let tx_input = TxInput {
            tx, 
            index,
            script_sig,
            sequence: 0xffffffff
        };
        self.inputs.push(Box::new(tx_input));
    }

    /// Adds an output to the transaction
    pub fn add_output(&mut self, value: u64, script_pub_key: Vec<u8>) {
        let tx_output = TxOutput {
            value,
            script_pub_key
        };
        self.outputs.push(Box::new(tx_output));
    }

    /// Returns a bytes vector representing the transaction
    pub fn bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.version.to_le_bytes());
        let inputs_counter = VariableInteger::new(self.inputs.len() as u64);
        bytes.extend_from_slice(&inputs_counter.bytes().as_slice());
        for input in self.inputs.iter() {
            bytes.extend_from_slice(input.bytes().as_slice());
        }
        let outputs_counter = VariableInteger::new(self.outputs.len() as u64);
        bytes.extend_from_slice(&outputs_counter.bytes().as_slice());
        for output in self.outputs.iter() {
            bytes.extend_from_slice(output.bytes().as_slice());
        }
        bytes.extend_from_slice(&self.lock_time.to_le_bytes());
        bytes
    }

    /// Returns the hash representing the transaction
    pub fn hash(&self) -> Hash32 {
        let mut hash = hash32(self.bytes().as_slice());
        hash.reverse();
        hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// This test is based on 
    /// https://bitcoin.stackexchange.com/questions/2859/how-are-transaction-hashes-calculated
    fn first_transaction() {
        let mut tx = Transaction::new();
        // Coinbase generation input
        tx.add_input([0 as u8; 32], 0xffffffff, hex::decode("4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73").unwrap());
        // Output 50 BTC
        tx.add_output(5_000_000_000, hex::decode("434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac").unwrap());
        
        assert_eq!("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000", hex::encode(tx.bytes()));
        assert_eq!("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b", hex::encode(tx.hash()));
    }
}
    
