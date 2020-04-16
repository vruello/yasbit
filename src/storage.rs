use crate::block;
use rocksdb::DB;

pub struct Storage {
    blocks: DB,
    transactions: DB,
    chain: DB,
}

impl Storage {
    pub fn new(blocks_path: &str, transactions_path: &str, chain_path: &str) -> Self {
        Storage {
            blocks: DB::open_default(blocks_path).unwrap(),
            transactions: DB::open_default(transactions_path).unwrap(),
            chain: DB::open_default(chain_path).unwrap(),
        }
    }
}
