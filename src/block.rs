use crate::crypto::{bytes_to_hash32, hash32, hash32_to_bytes, Hash32, Hashable};
use crate::merkle_tree;
use crate::transaction::Transaction;
use crate::utils;
use crate::variable_integer::VariableInteger;

/// A block is represented here
/// See https://en.bitcoin.it/wiki/Block
#[derive(Debug, PartialEq, Clone)]
pub struct Block {
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
    /// Returns a bytes array representing the block.
    /// Should be used in `hash`.
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

    pub fn validate(&self) -> bool {
        // FIXME: Do something
        true
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
    pub fn bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(&self.header.bytes());
        let tx_count = VariableInteger::new(self.transactions.len() as u64);
        bytes.extend_from_slice(&tx_count.bytes().as_slice());
        for transaction in &self.transactions {
            bytes.extend_from_slice(&transaction.bytes());
        }

        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut index = 0;

        let mut next_size = BlockHeader::length();
        let header = BlockHeader::from_bytes(&bytes[index..(index + next_size)]);
        index += next_size;

        let (tx_count, tx_count_size) = VariableInteger::from_bytes(&bytes[index..]).unwrap();
        index += tx_count_size;

        let mut transactions = Vec::new();
        for _ in 0..tx_count {
            let (tx, size) = Transaction::from_bytes(&bytes[index..]);
            index += size;
            transactions.push(Box::new(tx));
        }

        Block {
            header,
            transactions,
        }
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
        let mut hash = hash32(self.header.bytes().as_slice());
        hash.reverse();
        hash
    }
}

impl Hashable for BlockHeader {
    /// Returns the hash representing the block header
    fn hash(&self) -> Hash32 {
        let mut hash = hash32(self.bytes().as_slice());
        hash.reverse();
        hash
    }
}

pub fn genesis_block(version: u32, time: u32, nonce: u32, bits: u32, reward: u64) -> Block {
    let mut tx = Transaction::new();

    // Coinbase generation input
    tx.add_input(
        [0 as u8; 32],
        0xffffffff,
        hex::decode("04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73").unwrap());

    // Output reward
    tx.add_output(
        reward,
        hex::decode("4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac").unwrap());

    Block::new(
        version,
        [0; 32], // prev block
        time,    // time
        nonce,   // nonce
        bits,    // bits
        Box::new(tx),
    )
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::config;

    #[test]
    /// The test is based on
    /// https://www.blockchain.com/fr/btc/block/000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
    fn genesis_block_hash() {
        let config = config::main_config();
        let block = config.genesis_block;
        assert_eq!(
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
            hex::encode(block.hash())
        );

        assert_eq!(block, Block::from_bytes(&block.bytes()));
        assert_eq!(
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
            hex::encode(block.header.hash_merkle_root)
        );
    }

    #[test]
    fn test_genesis_block_hash() {
        let config = config::test_config();
        let block = config.genesis_block;
        assert_eq!(
            "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
            hex::encode(block.hash())
        );

        assert_eq!(block, Block::from_bytes(&block.bytes()));
        assert_eq!(
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
            hex::encode(block.header.hash_merkle_root)
        );
    }

    #[test]
    /// This test is based on
    /// https://bitcoin.stackexchange.com/questions/67791/calculate-hash-of-block-header
    fn block_502871() {
        // We manually set the merkle tree root hash to avoid adding all the transactions.
        let mut block = Block::new(
            536870912,
            utils::clone_into_array(
                &hex::decode("00000000000000000061abcd4f51d81ddba5498cff67fed44b287de0990b7266")
                    .unwrap(),
            ),
            1515252561,
            45291998,
            0x180091c1,
            Box::new(Transaction::new()),
        );

        block.header.hash_merkle_root = utils::clone_into_array(
            &hex::decode("871148c57dad60c0cde483233b099daa3e6492a91c13b337a5413a4c4f842978")
                .unwrap(),
        );

        assert_eq!(
            "00000000000000000020cf2bdc6563fb25c424af588d5fb7223461e72715e4a9",
            hex::encode(block.hash())
        );

        assert_eq!(block, Block::from_bytes(&block.bytes()));
    }
}
