extern crate openssl;

use std::error::Error;

use openssl::bn::BigNumContext;
use openssl::ec::*;
use openssl::ecdsa::EcdsaSig;
use openssl::hash::{hash, MessageDigest};
use openssl::nid::Nid;
use openssl::sha::sha256;

pub type Hash32 = [u8; 32];
pub type Hash20 = [u8; 20];

pub fn hash32(data: &[u8]) -> Hash32 {
    sha256(&sha256(data))
}

pub fn hash20(data: &[u8]) -> Hash20 {
    let mut array = [0; 20];
    for (i, byte) in hash(MessageDigest::ripemd160(), &sha256(data))
        .unwrap()
        .as_ref()
        .iter()
        .enumerate()
    {
        array[i] = *byte;
    }
    array
}

pub fn bytes_to_hash32(data: &[u8]) -> Result<Hash32, &'static str> {
    if data.len() != 32 {
        return Err("Invalid length");
    }

    let mut hash = [0u8; 32];
    for (i, c) in data.iter().rev().enumerate() {
        hash[i] = *c;
    }

    Ok(hash)
}

pub fn hash32_to_bytes(hash: &Hash32) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (i, c) in hash.iter().rev().enumerate() {
        bytes[i] = *c;
    }
    bytes
}

pub trait Hashable {
    fn hash(&self) -> Hash32;
}

pub fn sign(priv_key: &[u8], data: &Hash32) -> Vec<u8> {
    let key = EcKey::private_key_from_der(priv_key).unwrap();
    let sig = EcdsaSig::sign(data, &key).unwrap();

    sig.to_der().unwrap()
}

pub fn check_signature(
    pub_key_str: &[u8],
    sig_str: &[u8],
    data: &Hash32,
) -> Result<bool, Box<dyn Error>> {
    let sign = EcdsaSig::from_der(&sig_str)?;
    let group = EcGroup::from_curve_name(Nid::SECP256K1)?;
    let mut ctx = BigNumContext::new()?;
    let point = EcPoint::from_bytes(&group, pub_key_str, &mut ctx)?;
    let key = EcKey::from_public_key(&group, &point)?;

    Ok(sign.verify(data, &key)?)
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::utils;

    #[test]
    fn test_hash32() {
        let data = "babar".as_bytes();
        let h = hash32(data);
        assert_eq!(
            "c24daaa67001fc358d73b30060abdfa53c5ceb53982d9052c3d91b1d39\
             91eb40",
            hex::encode(h)
        );
    }

    #[test]
    fn test_hash20() {
        let data = "babar".as_bytes();
        let h = hash20(data);
        assert_eq!("7bf35740091d766c45e3c052aa173fa4af80027d", hex::encode(h));
    }

    #[test]
    fn test_generate_keys_sign_verify() {
        let mut ctx = BigNumContext::new().unwrap();
        let ec_group = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();

        // Generate (private,public) keys
        let ec_key = EcKey::generate(&ec_group).unwrap();
        //let private_key = (&ec_key).private_key(); // BigNum
        let public_key = (&ec_key).public_key(); // EcPoint

        //let private_key_bytes = private_key.to_vec();
        let public_key_bytes = public_key
            .to_bytes(&ec_group, PointConversionForm::UNCOMPRESSED, &mut ctx)
            .unwrap();
        //println!("Private key [{}]: {:?}", private_key_bytes.len(),
        //private_key_bytes);
        //println!("Public key [{}]: {:?}", public_key_bytes.len(),
        //public_key_bytes);

        // Sign "babar"
        let data = sha256("BABAR".as_bytes());
        let ecdsa_sig = EcdsaSig::sign(&data, &ec_key).unwrap();
        // Export signature in DER format
        let ecdsa_sig_der = ecdsa_sig.to_der().unwrap();
        //println!("Signature (DER): {:?}", ecdsa_sig_der);

        // Import signature from DER format and verify signature using public
        // key
        let test_sig = EcdsaSig::from_der(&ecdsa_sig_der).unwrap();
        let test_ec_point = EcPoint::from_bytes(&ec_group, &public_key_bytes, &mut ctx).unwrap();
        let test_ec_key = EcKey::from_public_key(&ec_group, &test_ec_point).unwrap();
        assert!(test_sig.verify(&data, &test_ec_key).unwrap());
    }

    #[test]
    fn test_check_signature_uncompressed() {
        // Compare result with openssl cli
        // Create a data file
        // echo -n BABAR > data
        // Generate EC private key in PEM format
        // > openssl ecparam -name secp256k1 -genkey -noout -out ecpriv.pem
        // Generate EC public key from private key in PEM format
        // > openssl ec -in ecpriv.pem -pubout -out ecpub.pem
        // Sign content of 'data' file hashed using sha256
        // > openssl dgst -sha256 -sign ecpriv.pem -binary < data > signature
        // Verify signature
        // > openssl dgst -sha256 -verify ecpub.pem -signature signature < data
        //
        // Use https://github.com/lapo-luchini/asn1js to decode ASN.1 in DER
        // format
        // To get the real private key (the random number)
        // > openssl ec -in ecpriv.pem -outform DER | tail -c +8 | head -c 32
        // To get the real public key (the point coordinates if using
        // uncompressed format)
        // > openssl ec -in ecpriv.pem -outform DER | tail -c 65
        let pub_key_str = hex::decode(
            "041c432310672596035e3590e3fbbc8834b0e6c\
             e624f77d9b6ecf2e8546b657cfee093c2302ca26\
             588e868014c6cddbc20041db82101f669c913109\
             86445b516d2",
        )
        .unwrap();
        //println!("uncompressed pub_key [{}] = {:?}", pub_key_str.len(),
        //pub_key_str);
        let sig_str = hex::decode(
            "304502210094dffda63cb7be9e0db8871b37bb20aba\
             b0f395e052a0ef28be526792447918002200b573e2e5\
             797db40f87d84b50a857510d94f78839041ca3e19728\
             f07656133cf",
        )
        .unwrap();
        let hash = sha256("BABAR".as_bytes());
        assert!(check_signature(&pub_key_str, &sig_str, &hash).unwrap());
    }

    #[test]
    fn test_check_signature_compressed() {
        // To get the real public key (the point coordinates if using
        // compressed format)
        // > openssl ec -in ecpriv.pem -outform DER -conv_form compressed
        //   | tail -c 33
        let pub_key_str = hex::decode(
            "021c432310672596035e3590e3fbbc8834b0e6c\
             e624f77d9b6ecf2e8546b657cfe",
        )
        .unwrap();
        let sig_str = hex::decode(
            "304502210094dffda63cb7be9e0db8871b37bb20aba\
             b0f395e052a0ef28be526792447918002200b573e2e5\
             797db40f87d84b50a857510d94f78839041ca3e19728\
             f07656133cf",
        )
        .unwrap();
        let hash = sha256("BABAR".as_bytes());
        assert!(check_signature(&pub_key_str, &sig_str, &hash).unwrap());
    }

    #[test]
    fn test_sign() {
        let ec_group = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();

        // Generate (private,public) keys
        let ec_key = EcKey::generate(&ec_group).unwrap();

        let data = hash32("babar".as_bytes());
        let signature = sign(&ec_key.private_key_to_der().unwrap(), &data);

        // Verify signature
        let ec_sig = EcdsaSig::from_der(&signature).unwrap();
        let pub_key = EcKey::from_public_key(&ec_group, ec_key.public_key()).unwrap();
        assert!(ec_sig.verify(&data, &pub_key).unwrap());
    }

    #[test]
    fn test_sign_check_sign() {
        let mut ctx = BigNumContext::new().unwrap();
        let ec_group = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();

        // Generate (private,public) keys
        let ec_key = EcKey::generate(&ec_group).unwrap();

        let data = hash32("babar".as_bytes());
        let signature = sign(&ec_key.private_key_to_der().unwrap(), &data);

        let pub_key_bytes = ec_key
            .public_key()
            .to_bytes(&ec_group, PointConversionForm::UNCOMPRESSED, &mut ctx)
            .unwrap();
        assert!(check_signature(&pub_key_bytes, &signature, &data).unwrap());
    }

    #[test]
    #[should_panic]
    fn test_to_hash32_panic() {
        let data: [u8; 1] = [0];
        let hash = bytes_to_hash32(&data).unwrap();
    }

    #[test]
    fn test_bytes_to_hash32() {
        let data = hex::decode("d39f608a7775b537729884d4e6633bb2105e55a16a14d31b0000000000000000")
            .unwrap();

        let hash = bytes_to_hash32(&data.as_slice()).unwrap();

        assert_eq!(hash.len(), 32);
        assert_eq!(
            hex::encode(hash),
            "00000000000000001bd3146aa1555e10b23b63e6d484987237b575778a609fd3"
        );
    }

    #[test]
    fn test_hash32_to_bytes() {
        let data = utils::clone_into_array(
            &hex::decode("d39f608a7775b537729884d4e6633bb2105e55a16a14d31b0000000000000000")
                .unwrap(),
        );

        let bytes = hash32_to_bytes(&data);
        assert_eq!(bytes.len(), 32);
        assert_eq!(
            hex::encode(&bytes),
            "00000000000000001bd3146aa1555e10b23b63e6d484987237b575778a609fd3"
        );
    }
}
