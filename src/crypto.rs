extern crate openssl;

use openssl::sha::sha256;

pub type Hash32 = [u8; 32];
pub type Hash20 = [u8; 20];

pub fn hash32(data: &[u8]) -> Hash32 {
    sha256(&sha256(data))
}

pub trait Hashable {
    fn hash(&self) -> Hash32;
}
