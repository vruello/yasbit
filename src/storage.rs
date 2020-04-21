use crate::block::{Block, BlockHeader};
use crate::crypto::{Hash32, Hashable};
use bincode;
use rocksdb::DB;
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fs::{read_dir, File, OpenOptions};
use std::io;
use std::io::prelude::*;
use std::marker::{Send, Sync};
use std::path;

#[derive(Debug)]
pub enum Error {
    DBOperation,
    AlreadyExists,
    FileOperation,
}

pub struct Storage {
    blocks: DB,
    transactions: DB,
    chain: DB,
    current_file: FilePos,
}

const BLOCK_PREFIX: char = 'b';

#[derive(Serialize, Deserialize)]
struct FilePosRecord {
    name: String,
    pos: u64,
}

struct FilePos {
    name: String,
    file: File,
    pos: u64,
}

impl FilePos {
    pub fn write(&mut self, bytes: &[u8]) -> Result<u64, Error> {
        let orig_pos = self.pos;
        if let Err(_) = self.file.write_all(bytes) {
            return Err(Error::FileOperation);
        }
        self.pos += (bytes.len() as u64);
        Ok(orig_pos)
    }
}

#[derive(Serialize, Deserialize)]
struct BlockIndexRecord {
    header: BlockHeader,
    height: u64,
    tx_number: u64,
    location: FilePosRecord,
}

fn get_last_block_file_pos(blocks_path: &str) -> FilePos {
    let mut entries = read_dir(blocks_path)
        .unwrap()
        .map(|res| res.unwrap().file_name())
        .collect::<Vec<OsString>>();

    // The order in which `read_dir` returns entries is not guaranteed. If reproducible
    // ordering is required the entries should be explicitly sorted.
    entries.sort();

    if entries.len() > 0 {
        let block_fname = entries.pop().unwrap();
        let block_path: path::PathBuf = [blocks_path, block_fname.to_str().unwrap()]
            .iter()
            .collect();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(block_path)
            .unwrap();
        let pos = file.metadata().unwrap().len();
        file.seek(io::SeekFrom::Start(pos)).unwrap();

        FilePos {
            name: block_fname.into_string().unwrap(),
            file,
            pos,
        }
    } else {
        let block_fname = "blk00001.dat";
        let block_path: path::PathBuf = [blocks_path, block_fname].iter().collect();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(block_path)
            .unwrap();
        let pos = file.metadata().unwrap().len();

        FilePos {
            name: block_fname.to_string(),
            file,
            pos,
        }
    }
}

impl Storage {
    pub fn new(
        blocks_path: &str,
        transactions_path: &str,
        chain_path: &str,
        blocks_file_path: &str,
    ) -> Self {
        let current_file = get_last_block_file_pos(blocks_file_path);
        log::info!(
            "Current block file is {} offset {}",
            current_file.name,
            current_file.pos
        );
        Storage {
            blocks: DB::open_default(blocks_path).unwrap(),
            transactions: DB::open_default(transactions_path).unwrap(),
            chain: DB::open_default(chain_path).unwrap(),
            current_file,
        }
    }

    pub fn store_block(&mut self, block: &Block) -> Result<(), Error> {
        // Check existence in blocks db
        let mut key = Vec::with_capacity(33);
        key.extend_from_slice(&block.hash());
        match self.blocks.get_pinned(&key) {
            Err(_) => return Err(Error::DBOperation),
            Ok(Some(metadata)) => return Err(Error::AlreadyExists),
            _ => (),
        };

        // Write to current block file
        log::info!(
            "Writing block {} in file {} offset {}",
            hex::encode(block.hash()),
            self.current_file.name,
            self.current_file.pos
        );
        let pos = self.current_file.write(&block.bytes())?;
        let location = FilePosRecord {
            name: self.current_file.name.clone(),
            pos,
        };

        let block_index_record = BlockIndexRecord {
            header: block.header.clone(), // FIXME
            height: 0,                    // TODO
            tx_number: (block.transactions.len() as u64),
            location,
        };

        // Store block index record
        self.blocks
            .put(&key, bincode::serialize(&block_index_record).unwrap());

        Ok(())
    }

    pub fn has_block(&mut self, hash: Hash32) -> Result<bool, Error> {
        let mut key = Vec::with_capacity(33);
        key.extend_from_slice(&hash);
        match self.blocks.get_pinned(&key) {
            Err(_) => return Err(Error::DBOperation),
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
        }
    }
}
