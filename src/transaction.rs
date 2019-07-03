use crate::crypto::Hash32;

/// A transaction is represented here
/// See https://en.bitcoin.it/wiki/Transactions
#[derive(Debug)]
pub struct Transaction {
    version: u32,
    flag: u16,
    inputs: Vec<Box<TxInput>>,
    outputs: Vec<Box<TxOutput>>,
    // FIXME Support witnesses
    lock_time: u32
}

#[derive(Debug)]
struct TxInput {
    tx: Hash32,
    index: u32,
    script_sig: Vec<u8>,
    sequence: u32,
}

#[derive(Debug)]
struct TxOutput {
    value: u64,
    script_pub_key: Vec<u8>
}

impl Transaction {

    /// Creates a new transaction
    pub fn new(version: u32) -> Self {
        Transaction {
            version, 
            flag: 0, 
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

    /// Returns the hash representing the transaction
    pub fn hash(&self) -> Hash32 {
      // TODO
        [0 as u8; 32]
    }
}
