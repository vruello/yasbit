
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
