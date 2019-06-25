extern crate crypto;
extern crate hex;

use crate::crypto::sha2::Sha256;
use crate::crypto::digest::Digest;
use std::time::SystemTime;

const HASH_SIZE: usize = 32;
const DEFAULT_DIFFICULTY: u8 = 2;

#[derive(Debug)]
struct Transaction {
    src: [u8; HASH_SIZE],
    dst: [u8; HASH_SIZE],
    amount: u32
}

impl Transaction {
    fn new(src: [u8; HASH_SIZE], dst: [u8; HASH_SIZE], amount: u32) -> Self {
        Transaction {
            src,
            dst,
            amount
        }
    }

    fn bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&self.src);
        bytes.extend_from_slice(&self.dst);
        bytes.extend_from_slice(&self.amount.to_be_bytes());;
        bytes
    }
}

#[derive(Debug)]
struct Block {
    // header
    version: u8,
    prev_block_hash: Option<[u8; HASH_SIZE]>,
    time: u64,
    nonce: Option<u64>,
    difficulty: u8,
    // content
    transactions: Vec<Box<Transaction>>
}

impl Block {

    fn new(version: u8, prev_block_hash: Option<[u8; HASH_SIZE]>, difficulty: u8) -> Self {
       Block {
           version,
           prev_block_hash,
           time: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs(),
           nonce: None,
           difficulty,
           transactions: Vec::new()
       }
    }

    fn bytes(&self) -> Vec<u8> {
        let mut bytes = vec![self.version];
        if let Some(hash) = self.prev_block_hash {
            for byte in hash.iter() {
                bytes.push(*byte);
            }
        }
        bytes.extend_from_slice(&self.time.to_be_bytes());
        let nonce = match self.nonce {
            Some(x) => x,
            None => 0
        };
        bytes.extend_from_slice(&nonce.to_be_bytes());
        bytes.push(self.difficulty);
        for transaction in self.transactions.iter() {
           bytes.extend_from_slice(&transaction.bytes()) 
        }
        bytes
    }

    fn hash(&self) -> [u8; HASH_SIZE] {
        let mut hasher = Sha256::new();
        hasher.input(&self.bytes());
        let mut res = [0; HASH_SIZE];
        hasher.result(&mut res);
        res
    }

    fn hash_str(&self) -> String {
        let hash = self.hash();
        hex::encode(hash)
    }

    fn add_transaction(&mut self, tr: Box<Transaction>) {
        self.transactions.push(tr);
    }

    fn is_valid(&self) -> bool {
        let hash = self.hash();
        let mut valid = true;
        for d in 0..self.difficulty {
            if hash[d as usize] != 0 {
                valid = false;
                break;
            }
        }
        valid
    }

    fn mine(&mut self) -> u64 {
        for x in 0..u64::max_value() {
            self.nonce = Some(x); 
            if self.is_valid() {
                return x;
            }
        }
        panic!("Could not find a valid nonce");
    }
}

#[derive(Debug)]
struct BlockChain {
    blocks: Vec<Box<Block>>,
    next_difficulty: u8
}

impl BlockChain {
    fn new() -> Self {
        BlockChain {
            blocks: Vec::new(),
            next_difficulty: DEFAULT_DIFFICULTY
        }
    }

    fn add_block(&mut self, block: Box<Block>) {
        assert!(block.is_valid()); 
        assert_eq!(block.difficulty, self.next_difficulty);
        if let Some(last_block) = self.blocks.last() {
            assert_eq!(last_block.hash(), block.prev_block_hash.unwrap())
        }
        self.blocks.push(block);
    }

    fn last_block_hash(&self) -> Option<[u8; HASH_SIZE]> {
        if let Some(last_block) = self.blocks.last() {
            return Some(last_block.hash());
        }
        return None;
    }
}

fn main() {
    let mut blockchain = BlockChain::new();
    
    // Add a genesic block with no transactions

    let mut genesis_block = Block::new(1, None, blockchain.next_difficulty); 
   
    genesis_block.mine();
    
    println!("Genesis block : {:?}", genesis_block);
    println!("Hash: {}", genesis_block.hash_str()); 
    
    blockchain.add_block(Box::new(genesis_block));
    
    println!("{:?}", blockchain);
    
    // Add a new block with one transaction
    
    let mut block = Block::new(1, Some(blockchain.last_block_hash().unwrap()), blockchain.next_difficulty);
    
    let mut hasher = Sha256::new();
    // src is SHA_256("babar")
    hasher.input_str("babar");
    let mut babar_hashed: [u8; HASH_SIZE] = [0; HASH_SIZE];
    hasher.result(&mut babar_hashed);
    hasher.reset();
    // dst is SHA_256("toto")
    hasher.input_str("toto");
    let mut toto_hashed: [u8; HASH_SIZE] = [0; HASH_SIZE];
    hasher.result(&mut toto_hashed);

    let tr1 = Box::new(Transaction::new(babar_hashed, toto_hashed, 10));
    block.add_transaction(tr1);
     
    block.mine();
    
    println!("Block : {:?}", block);
    println!("Hash: {}", block.hash_str());

    blockchain.add_block(Box::new(block));
  
    println!("{:?}", blockchain);
}

