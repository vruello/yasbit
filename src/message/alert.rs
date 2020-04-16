use crate::config;
use crate::crypto;
use crate::message;
use crate::message::MessageCommand;
use crate::node;
use crate::utils;
use crate::variable_integer::VariableInteger;

// FIXME: alert system is deprecated. Alerts can not be trusted anymore.
// Keys have been disclosed here: https://bitcoin.org/en/posts/alert-key-and-vulnerabilities-disclosure

// FIXME: There should be a variable of a constant saying on which network we are
// so that we can choose in which pub key we trust.

// Public key used by the developers of Satoshi's client for signing alerts
static TRUSTED_PUBLIC_KEYS: &'static [&'static str] = &[
    "04fc9702847840aaf195de8442ebecedf5b095cdbb9bc716bda9110971b28a49e0ead8564ff0db22209e0374782c093bb899692d524e9d6a6956e7c5ecbcd68284", // Main net
    "04302390343f91cc401d56d68b123028bf52e5fca1939df127f63c6467cdf9c8e2c14b61104cf817d0b780da337893ecc4aaff1309e536162dabbdb45200ca2b0a", // Test net
];

// This key will be used to emit alert messages
// This is the private key of the test net alert system
static SIGNING_KEY: &'static str =
    "308201130201010420474d447aa6f46b4f45f67f21180a5de2722fc807401c4c4d95fdae64b3d6c294a081a53081a2020101302c06072a8648ce3d0101022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f300604010004010704410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141020101a14403420004302390343f91cc401d56d68b123028bf52e5fca1939df127f63c6467cdf9c8e2c14b61104cf817d0b780da337893ecc4aaff1309e536162dabbdb45200ca2b0a";

const NAME: &str = "alert";

#[derive(PartialEq, Debug)]
pub struct MessageAlert {
    version: u32,     // Alert format version
    relay_until: u64, // Timestamp beyond which nodes should stop relaying the alert
    expiration: u64,  // Timestamp beyond which this alert is no longer in effect
    id: u32,          // Unique ID number for this alert
    cancel: u32,      // All alerts with an ID number less than or equal to this number
    // should be cancelled: deleted and not accepted in the future
    set_cancel: Vec<u32>, // All alerts IDs contained in this sed should be cancelled
    // as above
    min_ver: u32, // This alert only applies to versions greater than or equal to
    // this version.
    max_ver: u32, // This alert only applies to versions less than or equal to
    // this version.
    sub_vers: Vec<String>, // Probably useless
    priority: u32,         // Relative priority compared to other alerts
    comment: String,       // A comment on the alert that is not displayed
    status_bar: String,    // The alert message that is displayed to the user
    reserved: String,      // Reserved
    trusted: bool,         // set when MessageAlert has been signed by a trusted third party
}

impl message::MessageCommand for MessageAlert {
    fn name(&self) -> [u8; 12] {
        let mut command = [0 as u8; 12];
        for (i, c) in NAME.char_indices() {
            command[i] = c as u8;
        }
        command
    }

    /// Can not be computed without signing, which results in a kind of random length
    fn length(&self) -> u32 {
        panic!("Not implemented");
    }

    fn bytes(&self) -> Vec<u8> {
        let payload_bytes = self.payload_bytes();
        let mut bytes = Vec::new();

        let payload_len = VariableInteger::new(payload_bytes.len() as u64);
        bytes.extend_from_slice(payload_len.bytes().as_slice());
        bytes.extend_from_slice(payload_bytes.as_slice());

        let key = hex::decode(SIGNING_KEY).unwrap();
        let sig = crypto::sign(&key, &crypto::hash32(&payload_bytes));
        let sig_len = VariableInteger::new(sig.len() as u64);
        bytes.extend_from_slice(sig_len.bytes().as_slice());
        bytes.extend_from_slice(sig.as_slice());

        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        let mut index = 0;
        let (_, payload_len_size) = VariableInteger::from_bytes(&bytes[index..]).unwrap();
        index += payload_len_size;

        let version = u32::from_le_bytes(utils::clone_into_array(&bytes[index..(index + 4)]));
        index += 4;

        let relay_until = u64::from_le_bytes(utils::clone_into_array(&bytes[index..(index + 8)]));
        index += 8;

        let expiration = u64::from_le_bytes(utils::clone_into_array(&bytes[index..(index + 8)]));
        index += 8;

        let id = u32::from_le_bytes(utils::clone_into_array(&bytes[index..(index + 4)]));
        index += 4;

        let cancel = u32::from_le_bytes(utils::clone_into_array(&bytes[index..(index + 4)]));
        index += 4;

        let (set_cancel_len, set_cancel_len_size) =
            VariableInteger::from_bytes(&bytes[index..]).unwrap();
        index += set_cancel_len_size;
        let mut set_cancel = Vec::with_capacity(set_cancel_len as usize);
        for _ in 0..set_cancel_len {
            let cancel_elt =
                u32::from_le_bytes(utils::clone_into_array(&bytes[index..(index + 4)]));
            index += 4;
            set_cancel.push(cancel_elt);
        }

        let min_ver = u32::from_le_bytes(utils::clone_into_array(&bytes[index..(index + 4)]));
        index += 4;

        let max_ver = u32::from_le_bytes(utils::clone_into_array(&bytes[index..(index + 4)]));
        index += 4;

        let (sub_vers_len, sub_vers_len_size) =
            VariableInteger::from_bytes(&bytes[index..]).unwrap();
        index += sub_vers_len_size;
        let mut sub_vers = Vec::with_capacity(sub_vers_len as usize);
        for _ in 0..sub_vers_len {
            let (sub_ver_len, sub_ver_len_size) =
                VariableInteger::from_bytes(&bytes[index..]).unwrap();
            index += sub_ver_len_size;
            let sub_ver = std::str::from_utf8(&bytes[index..(index + (sub_ver_len as usize))])
                .unwrap()
                .to_owned();
            index += sub_ver_len as usize;
            sub_vers.push(sub_ver);
        }

        let priority = u32::from_le_bytes(utils::clone_into_array(&bytes[index..(index + 4)]));
        index += 4;

        let (comment_len, comment_len_size) = VariableInteger::from_bytes(&bytes[index..]).unwrap();
        index += comment_len_size;
        let comment = std::str::from_utf8(&bytes[index..(index + (comment_len as usize))])
            .unwrap()
            .to_owned();
        index += comment_len as usize;

        let (status_bar_len, status_bar_len_size) =
            VariableInteger::from_bytes(&bytes[index..]).unwrap();
        index += status_bar_len_size;
        let status_bar = std::str::from_utf8(&bytes[index..(index + (status_bar_len as usize))])
            .unwrap()
            .to_owned();
        index += status_bar_len as usize;

        let (reserved_len, reserved_len_size) =
            VariableInteger::from_bytes(&bytes[index..]).unwrap();
        index += reserved_len_size;
        let reserved = std::str::from_utf8(&bytes[index..(index + (reserved_len as usize))])
            .unwrap()
            .to_owned();
        index += reserved_len as usize;

        let payload_bytes = &bytes[payload_len_size..index];
        let (_, signature_len_size) = VariableInteger::from_bytes(&bytes[index..]).unwrap();
        index += signature_len_size;

        let signature = &bytes[index..];
        let mut trusted = false;
        for pub_key in TRUSTED_PUBLIC_KEYS {
            trusted = match crypto::check_signature(
                &hex::decode(pub_key).unwrap(),
                signature,
                &crypto::hash32(payload_bytes),
            ) {
                Ok(res) => res,
                Err(_) => false,
            };
            if trusted {
                break;
            }
        }

        MessageAlert {
            version,
            relay_until,
            expiration,
            id,
            cancel,
            set_cancel,
            min_ver,
            max_ver,
            sub_vers,
            priority,
            comment,
            status_bar,
            reserved,
            trusted,
        }
    }

    fn handle(&self, node: &mut node::Node, config: &config::Config) {}
}

impl MessageAlert {
    pub fn new(
        version: u32,
        relay_until: u64,
        expiration: u64,
        id: u32,
        cancel: u32,
        set_cancel: Vec<u32>,
        min_ver: u32,
        max_ver: u32,
        sub_vers: Vec<String>,
        priority: u32,
        comment: String,
        status_bar: String,
        reserved: String,
        trusted: bool,
    ) -> Self {
        MessageAlert {
            version,
            relay_until,
            expiration,
            id,
            cancel,
            set_cancel,
            min_ver,
            max_ver,
            sub_vers,
            priority,
            comment,
            status_bar,
            reserved,
            trusted,
        }
    }

    fn payload_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(&self.relay_until.to_le_bytes());
        bytes.extend_from_slice(&self.expiration.to_le_bytes());
        bytes.extend_from_slice(&self.id.to_le_bytes());
        bytes.extend_from_slice(&self.cancel.to_le_bytes());

        let set_cancel_len = VariableInteger::new(self.set_cancel.len() as u64);
        bytes.extend_from_slice(set_cancel_len.bytes().as_slice());

        for cancel_id in self.set_cancel.iter() {
            bytes.extend_from_slice(&cancel_id.to_le_bytes());
        }

        bytes.extend_from_slice(&self.min_ver.to_le_bytes());
        bytes.extend_from_slice(&self.max_ver.to_le_bytes());

        let sub_vers_len = VariableInteger::new(self.sub_vers.len() as u64);
        bytes.extend_from_slice(sub_vers_len.bytes().as_slice());
        for sub_ver in self.sub_vers.iter() {
            let sub_ver_len = VariableInteger::new(sub_ver.len() as u64);
            bytes.extend_from_slice(sub_ver_len.bytes().as_slice());
            bytes.extend_from_slice(sub_ver.as_bytes());
        }

        bytes.extend_from_slice(&self.priority.to_le_bytes());

        let comment_len = VariableInteger::new(self.comment.len() as u64);
        bytes.extend_from_slice(comment_len.bytes().as_slice());
        bytes.extend_from_slice(self.comment.as_bytes());

        let status_bar_len = VariableInteger::new(self.status_bar.len() as u64);
        bytes.extend_from_slice(status_bar_len.bytes().as_slice());
        bytes.extend_from_slice(self.status_bar.as_bytes());

        let reserved_len = VariableInteger::new(self.reserved.len() as u64);
        bytes.extend_from_slice(reserved_len.bytes().as_slice());
        bytes.extend_from_slice(self.reserved.as_bytes());
        bytes
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_message_alert() {
        let alert = MessageAlert::new(
            1,
            1329620535,
            1329792435,
            1010,
            1009,
            Vec::new(),
            10000,
            61000,
            Vec::new(),
            100,
            String::default(),
            String::from("See bitcoin.org/feb20 if you have trouble connecting after 20 February"),
            String::default(),
            true,
        );

        let bytes = alert.bytes();

        // Check payload
        let expected_bytes = hex::decode("010000003766404f00000000b305434f00000000f2030000f1030000001027000048ee00000064000000004653656520626974636f696e2e6f72672f666562323020696620796f7520686176652074726f75626c6520636f6e6e656374696e6720616674657220323020466562727561727900").unwrap();
        assert_eq!(
            &bytes[1..(expected_bytes.len() + 1)],
            expected_bytes.as_slice()
        );

        // Check sig size
        // Sig size must be between 70 and 72, therefore we assume that
        // it is serialized in 1 byte.
        assert_eq!(
            bytes[(expected_bytes.len() + 2)..].len() as u8,
            bytes[expected_bytes.len() + 1]
        );

        // Parse
        let new_alert = MessageAlert::from_bytes(&bytes);
        assert_eq!(new_alert, alert);
    }

    #[test]
    fn test_parse_message_alert() {
        let bytes = hex::decode("73010000003766404f00000000b305434f00000000f2030000f1030000001027000048ee00000064000000004653656520626974636f696e2e6f72672f666562323020696620796f7520686176652074726f75626c6520636f6e6e656374696e67206166746572203230204665627275617279004730450221008389df45f0703f39ec8c1cc42c13810ffcae14995bb648340219e353b63b53eb022009ec65e1c1aaeec1fd334c6b684bde2b3f573060d5b70c3a46723326e4e8a4f1").unwrap();
        let alert = MessageAlert::from_bytes(&bytes);
        let expected = MessageAlert::new(
            1,
            1329620535,
            1329792435,
            1010,
            1009,
            Vec::new(),
            10000,
            61000,
            Vec::new(),
            100,
            String::default(),
            String::from("See bitcoin.org/feb20 if you have trouble connecting after 20 February"),
            String::default(),
            true,
        );
        assert_eq!(alert, expected);
    }

    #[test]
    fn test_message_alert_serialize_deserialize() {
        let alert = MessageAlert::new(
            1,
            1329620535,
            1329792435,
            1010,
            1009,
            vec![1, 2, 3],
            10000,
            61000,
            vec![String::from("babar"), String::from("Hello world")],
            100,
            String::from("toto"),
            String::from("See bitcoin.org/feb20 if you have trouble connecting after 20 February"),
            String::default(),
            true,
        );
        let bytes = alert.bytes();
        let new_alert = MessageAlert::from_bytes(&bytes);
        assert_eq!(alert, new_alert);
    }
}
