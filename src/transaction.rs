use crate::crypto::{hash32, Hash32};

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
        bytes.extend_from_slice(self.script_sig.as_slice());
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
    pub fn new(version: u32) -> Self {
        Transaction {
            version, 
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0xffffffff
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
        // TODO test
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(&(self.inputs.len() as u32).to_le_bytes());
        for input in self.inputs.iter() {
            bytes.extend_from_slice(input.bytes().as_slice());
        }
        bytes.extend_from_slice(&(self.outputs.len() as u32).to_le_bytes());
        for output in self.outputs.iter() {
            bytes.extend_from_slice(output.bytes().as_slice());
        }
        bytes.extend_from_slice(&self.lock_time.to_le_bytes());
        bytes
    }

    /// Returns the hash representing the transaction
    pub fn hash(&self) -> Hash32 {
        // TODO test
        let bytes = self.bytes();
        hash32(bytes.as_slice())
    }
}
