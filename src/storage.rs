use rocksdb::DB;

pub struct Storage {
    blocks: DB,
    transactions: DB,
}

impl Storage {
    pub fn new(blocks_path: &str, transactions_path: &str) -> Self {
        Storage {
            blocks: DB::open_default(blocks_path).unwrap(),
            transactions: DB::open_default(transactions_path).unwrap(),
        }
    }
}
