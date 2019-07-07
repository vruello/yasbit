extern crate openssl;

use std::error::Error;

use openssl::nid::Nid;
use openssl::ec::*;
use openssl::bn::BigNumContext;
use openssl::sha::sha256;
use openssl::hash::{MessageDigest, hash};
use openssl::ecdsa::EcdsaSig;

pub type Hash32 = [u8; 32];
pub type Hash20 = [u8; 20];

pub fn hash32(data: &[u8]) -> Hash32 {
    sha256(&sha256(data))
}

pub fn hash20(data: &[u8]) -> Hash20 { 
    let mut array = [0; 20];
    for (i, byte) in hash(MessageDigest::ripemd160(), &sha256(data)).unwrap().as_ref().iter().enumerate() {
        array[i] = *byte;
    }
    array
}

pub trait Hashable {
    fn hash(&self) -> Hash32;
}

pub fn check_signature(pub_key_str: &Vec<u8>, sig_str: &Vec<u8>, tx_hash: Hash32) -> Result<bool, Box<dyn Error>> {
    let sign = EcdsaSig::from_der(&sig_str)?;
    let group = EcGroup::from_curve_name(Nid::SECP256K1)?;
    let mut ctx = BigNumContext::new()?;
    let point = EcPoint::from_bytes(&group, pub_key_str, &mut ctx)?;
    let key = EcKey::from_public_key(&group, &point)?;

    Ok(sign.verify(&tx_hash, &key)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash32() {
        let data = "babar".as_bytes();
        let h = hash32(data);
        assert_eq!("c24daaa67001fc358d73b30060abdfa53c5ceb53982d9052c3d91b1d3991eb40", hex::encode(h));
    }

    #[test]
    fn test_hash20() {
        let data = "babar".as_bytes();
        let h = hash20(data);
        assert_eq!("7bf35740091d766c45e3c052aa173fa4af80027d", hex::encode(h));
    }

    #[test]
    fn test_check_signature() {
        // TODO
        panic!("Test not implemented");
    }
}
