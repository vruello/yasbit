use crate::crypto::Hash32;
use std::time::SystemTime;
use crate::transaction::Transaction;

/// A block is represented here
/// See https://en.bitcoin.it/wiki/Block
#[derive(Debug)]
pub struct Block {
    magic_no: u32, // should always be 0xD9B4BEF9
    header: BlockHeader,
    transactions: Vec<Box<Transaction>>
}

/// A block header is represented here
/// See https://en.bitcoin.it/wiki/Block_hashing_algorithm
#[derive(Debug)]
struct BlockHeader {
    version: u32, // block version number
    hash_prev_block: Option<Hash32>, // hash of previous block header
    hash_merkle_root: Option<Hash32>, // hash based on all transactions in the block
    time: u64, // block timestamp. FIXME: should be 4 bytes long.
    bits: u32, // current target, must be represented in 32 bits
    nonce: u32 // initialized to 0
}

impl Block {

    pub fn new(hash_prev_block: Option<Hash32>, difficulty: u32) -> Self {
        let block_header = BlockHeader {
           version: 1,
           hash_prev_block,
           hash_merkle_root: None,
           time: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs(),
           bits: difficulty,
           nonce: 0,
        };
        
        Block {
            magic_no: 0xD9B4BEF9,
            header: block_header,
            transactions: Vec::new()
        }
    }

    /// Returns a bytes array representing the block.
    /// Should be used in `hash`.
    fn bytes(&self) -> Vec<u8> {
        // TODO
        // let mut bytes = vec![self.version];
        // if let Some(hash) = self.prev_block_hash {
        //     for byte in hash.iter() {
        //         bytes.push(*byte);
        //     }
        // }
        // bytes.extend_from_slice(&self.time.to_be_bytes());
        // let nonce = match self.nonce {
        //     Some(x) => x,
        //     None => 0
        // };
        // bytes.extend_from_slice(&nonce.to_be_bytes());
        // bytes.push(self.difficulty);
        // for transaction in self.transactions.iter() {
        //    bytes.extend_from_slice(&transaction.bytes()) 
        // }
        // bytes
        Vec::new()
    }

    /// Returns the hash representing the block
    pub fn hash(&self) -> Vec<u8> {
        // TODO
        Vec::new()
    }

    /// Adds the given transaction to the block
    pub fn add_tx(&mut self, tr: Box<Transaction>) {
        self.transactions.push(tr);
    }

    /// Returns a boolean whether the block is valid or not.
    pub fn is_valid(&self) -> bool {
        // TODO 
        false
    }

    /// Try to find a valid nonce for the block.
    fn mine(&mut self) -> u32 {
        for x in 0..u32::max_value() {
            self.header.nonce = x; 
            if self.is_valid() {
                return x;
            }
        }
        panic!("Could not find a valid nonce");
    }
}
