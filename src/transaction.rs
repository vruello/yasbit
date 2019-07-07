extern crate hex;

use crate::crypto::{hash32, Hash32, Hashable};
use crate::variable_integer::VariableInteger;


/// A transaction is represented here
/// See https://en.bitcoin.it/wiki/Transactions
// FIXME Support flag and witnesses
#[derive(Debug, Clone)]
pub struct Transaction {
    version: u32,
    pub inputs: Vec<Box<TxInput>>,
    pub outputs: Vec<Box<TxOutput>>,
    lock_time: u32
}

#[derive(Debug, Clone)]
pub struct TxInput {
    tx: Hash32,
    index: u32,
    pub script_sig: Vec<u8>,
    sequence: u32,
}

impl TxInput {
    fn bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.tx);

        bytes.extend_from_slice(&self.index.to_le_bytes());
        
        let script_sig_size = VariableInteger::new(self.script_sig.len() as u64);
        bytes.extend_from_slice(&script_sig_size.bytes().as_slice());

        bytes.extend_from_slice(&self.script_sig.as_slice());
        bytes.extend_from_slice(&self.sequence.to_le_bytes());
        bytes
    }
}

#[derive(Debug, Clone)]
pub struct TxOutput {
    value: u64,
    script_pub_key: Vec<u8>
}

impl TxOutput {
    fn bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.value.to_le_bytes());
        
        let script_pub_key_size = VariableInteger::new(self.script_pub_key.len() as u64);
        bytes.extend_from_slice(&script_pub_key_size.bytes().as_slice());
        
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

}

impl Hashable for Transaction {
    /// Returns the hash representing the transaction
    fn hash(&self) -> Hash32 {
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
    fn genesis_block_transaction() {
        let mut tx = Transaction::new();
        // Coinbase generation input
        tx.add_input([0 as u8; 32], 0xffffffff, hex::decode("04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73").unwrap());
        // Output 50 BTC
        tx.add_output(5_000_000_000, hex::decode("4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac").unwrap());
        
        assert_eq!("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000", hex::encode(tx.bytes()));
        assert_eq!("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b", hex::encode(tx.hash()));
    }

    #[test]
    fn block_125552_60c25() {
        let mut tx = Transaction::new();
        let mut prev_tx = [0; 32];
        for (i, byte) in hex::decode("738d466ff93e7857d07138b5a5a75e83a964e3c9977d2603308ecc9b667962ad").unwrap().iter().enumerate() {
            prev_tx[31 - i] = *byte;
        }

        tx.add_input(
            prev_tx,
            0,
            hex::decode("4930460221009805aa00cb6f80ca984584d4ca40f637fc948e3dbe159ea5c4eb6941bf4eb763022100e1cc0852d3f6eb87839edca1f90169088ed3502d8cde2f495840acac69eefc9801410486477e6a23cb25c9a99f0c467c6fc86197e718ebfd41d1aef7cc3cbd75197c1f1aaba985b22b366a0729ccb8aa38277809d6d218cf4077ac9f29a953b5435222").unwrap());

        tx.add_output(50000000, hex::decode("76a9146f31097e564b9d54ebad662d5c4b5621c18ff52388ac").unwrap());
        tx.add_output(2900000000, hex::decode("76a9147228033b48b380900501c39c61da4ab453ca88e888ac").unwrap());

        assert_eq!("0100000001ad6279669bcc8e3003267d97c9e364a9835ea7a5b53871d057783ef96f468d73000000008c4930460221009805aa00cb6f80ca984584d4ca40f637fc948e3dbe159ea5c4eb6941bf4eb763022100e1cc0852d3f6eb87839edca1f90169088ed3502d8cde2f495840acac69eefc9801410486477e6a23cb25c9a99f0c467c6fc86197e718ebfd41d1aef7cc3cbd75197c1f1aaba985b22b366a0729ccb8aa38277809d6d218cf4077ac9f29a953b5435222ffffffff0280f0fa02000000001976a9146f31097e564b9d54ebad662d5c4b5621c18ff52388ac007ddaac000000001976a9147228033b48b380900501c39c61da4ab453ca88e888ac00000000", hex::encode(tx.bytes()));

        assert_eq!("60c25dda8d41f8d3d7d5c6249e2ea1b05a25bf7ae2ad6d904b512b31f997e1a1", hex::encode(tx.hash()));
    }

}
    
