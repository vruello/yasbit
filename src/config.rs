use crate::block::{genesis_block, Block};

#[derive(Debug, Clone)]
pub struct Config {
    pub genesis_block: Block,
    pub magic: u32,
    pub dns_seeds: Vec<String>,
    pub port: u16,
}

pub fn main_config() -> Config {
    Config {
        genesis_block: genesis_block(
            1,             // version
            1231006505,    // time
            2083236893,    // nonce
            486604799,     // bits
            5_000_000_000, // reward
        ),
        magic: 0xD9B4BEF9,
        dns_seeds: vec![
            "seed.bitcoin.sipa.be".to_string(),
            "dnsseed.bluematt.me".to_string(),
            "dnsseed.bitcoin.dashjr.org".to_string(),
            "seed.bitcoinstats.com".to_string(),
            "seed.bitcoin.jonasschnelli.ch".to_string(),
            "seed.btc.petertodd.org".to_string(),
            "seed.bitcoin.sprovoost.nl".to_string(),
            "nsseed.emzy.de".to_string(),
        ],
        port: 8333,
    }
}

pub fn test_config() -> Config {
    Config {
        genesis_block: genesis_block(
            1,             // version
            1296688602,    // time
            414098458,     // nonce
            0x1d00ffff,    // bits
            5_000_000_000, // reward
        ),
        magic: 0x0709110B,
        dns_seeds: vec![
            "testnet-seed.bitcoin.jonasschnelli.ch".to_string(),
            "seed.tbtc.petertodd.org".to_string(),
            "seed.testnet.bitcoin.sprovoost.nl".to_string(),
            "testnet-seed.bluematt.me".to_string(),
        ],
        port: 18333,
    }
}
