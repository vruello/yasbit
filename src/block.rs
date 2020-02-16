use crate::crypto::{bytes_to_hash32, hash32, hash32_to_bytes, Hash32, Hashable};
use crate::merkle_tree;
use crate::transaction::Transaction;
use crate::utils;

/// A block is represented here
/// See https://en.bitcoin.it/wiki/Block
#[derive(Debug)]
pub struct Block {
    magic_no: u32, // should always be 0xD9B4BEF9
    pub header: BlockHeader,
    transactions: Vec<Box<Transaction>>,
}

/// A block header is represented here
/// See https://en.bitcoin.it/wiki/Block_hashing_algorithm
#[derive(Debug, PartialEq, Clone)]
pub struct BlockHeader {
    version: u32,             // block version number
    hash_prev_block: Hash32,  // hash of previous block header
    hash_merkle_root: Hash32, // hash based on all transactions in the block
    time: u32,                // block timestamp
    bits: u32,                // current target, must be represented in 32 bits
    nonce: u32,               // initialized to 0
}

impl BlockHeader {
    pub fn bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(&hash32_to_bytes(&self.hash_prev_block));
        bytes.extend_from_slice(&hash32_to_bytes(&self.hash_merkle_root));
        bytes.extend_from_slice(&self.time.to_le_bytes());
        bytes.extend_from_slice(&self.bits.to_le_bytes());
        bytes.extend_from_slice(&self.nonce.to_le_bytes());

        bytes
    }

    pub fn length() -> usize {
        80
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut index = 0;
        let mut next_size = 4;
        let version =
            u32::from_le_bytes(utils::clone_into_array(&bytes[index..(index + next_size)]));
        index += next_size;

        next_size = 32;
        let hash_prev_block =
            utils::clone_into_array(&bytes_to_hash32(&bytes[index..(index + next_size)]).unwrap());
        index += next_size;

        let hash_merkle_root =
            utils::clone_into_array(&bytes_to_hash32(&bytes[index..(index + next_size)]).unwrap());
        index += next_size;

        next_size = 4;
        let time = u32::from_le_bytes(utils::clone_into_array(&bytes[index..(index + next_size)]));
        index += next_size;
        let bits = u32::from_le_bytes(utils::clone_into_array(&bytes[index..(index + next_size)]));
        index += next_size;
        let nonce = u32::from_le_bytes(utils::clone_into_array(&bytes[index..(index + next_size)]));
        index += next_size;

        Self {
            version,
            hash_prev_block,
            hash_merkle_root,
            time,
            bits,
            nonce,
        }
    }
}

impl Block {
    pub fn new(
        version: u32,
        hash_prev_block: Hash32,
        time: u32,
        nonce: u32,
        bits: u32,
        first_tx: Box<Transaction>,
    ) -> Self {
        let block_header = BlockHeader {
            version,
            hash_prev_block,
            hash_merkle_root: [0; 32], // Updated with block.update_merkle_root()
            time,
            bits,
            nonce,
        };

        let mut block = Block {
            magic_no: 0xD9B4BEF9,
            header: block_header,
            transactions: vec![first_tx],
        };

        block.update_merkle_root();

        block
    }

    fn update_merkle_root(&mut self) {
        let mk = merkle_tree::MerkleTree::new(&self.transactions);
        self.header.hash_merkle_root = mk.root().unwrap()
    }

    /// Returns a bytes array representing the block.
    /// Should be used in `hash`.
    fn bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        // version
        bytes.extend_from_slice(&self.header.version.to_le_bytes());
        // prev block hash reversed
        let mut prev_block = self.header.hash_prev_block.clone();
        prev_block.reverse();
        bytes.extend_from_slice(&prev_block);
        // merkle root hash reversed
        let mut merkle_root = self.header.hash_merkle_root.clone();
        merkle_root.reverse();
        bytes.extend_from_slice(&merkle_root);
        // time in little endian
        bytes.extend_from_slice(&self.header.time.to_le_bytes());
        // bits in little endian
        bytes.extend_from_slice(&self.header.bits.to_le_bytes());
        // nonce in little endian
        bytes.extend_from_slice(&self.header.nonce.to_le_bytes());
        bytes
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

impl Hashable for Block {
    /// Returns the hash representing the block
    fn hash(&self) -> Hash32 {
        let mut hash = hash32(self.bytes().as_slice());
        hash.reverse();
        hash
    }
}

pub fn genesis_block() -> Block {
    let mut tx = Transaction::new();
    // Coinbase generation input
    tx.add_input(
        [0 as u8; 32],
        0xffffffff,
        hex::decode("04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73").unwrap());
    // Output 50 BTC
    tx.add_output(
        5_000_000_000,
        hex::decode("4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac").unwrap());

    Block::new(
        1,
        [0; 32],    // prev block
        1231006505, // time
        2083236893, // nonce
        486604799,  // bits
        Box::new(tx),
    )
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    /// The test is based on
    /// https://www.blockchain.com/fr/btc/block/000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
    fn genesis_block_hash() {
        let block = genesis_block();
        assert_eq!(
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
            hex::encode(block.hash())
        );
    }

    #[test]
    /// This test is based on
    /// https://bitcoin.stackexchange.com/questions/67791/calculate-hash-of-block-header
    fn block_502871() {
        // We must build manually the hash (type Hash32)
        let mut prev_hash = [0; 32];
        for (i, byte) in
            hex::decode("00000000000000000061abcd4f51d81ddba5498cff67fed44b287de0990b7266")
                .unwrap()
                .iter()
                .enumerate()
        {
            prev_hash[i] = *byte;
        }

        // We manually set the merkle tree root hash to avoid adding all the transactions.
        let mut block = Block::new(
            536870912,
            prev_hash,
            1515252561,
            45291998,
            0x180091c1,
            Box::new(Transaction::new()),
        );

        let mut merkle_root = [0; 32];
        for (i, byte) in
            hex::decode("871148c57dad60c0cde483233b099daa3e6492a91c13b337a5413a4c4f842978")
                .unwrap()
                .iter()
                .enumerate()
        {
            merkle_root[i] = *byte;
        }

        block.header.hash_merkle_root = merkle_root;

        assert_eq!(
            "00000000000000000020cf2bdc6563fb25c424af588d5fb7223461e72715e4a9",
            hex::encode(block.hash())
        );
    }
}
