use std::error::Error;
use std::fmt;

#[derive(Debug, Clone)]
struct ArrayTooLargeError();

impl fmt::Display for ArrayTooLargeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "array length must not be larger than 9.")
    }
}

impl Error for ArrayTooLargeError {}

pub struct VariableInteger {
    integer: u64,
}

/// This is the implementation of the Variable Integer Scheme used in BTC
/// https://en.bitcoin.it/wiki/Protocol_specification#Variable_length_integer
impl VariableInteger {
    pub fn new(integer: u64) -> Self {
        VariableInteger { integer }
    }

    pub fn bytes(&self) -> Vec<u8> {
        if self.integer < 0xFD {
            vec![self.integer as u8]
        } else if self.integer <= 0xFFFF {
            let mut bytes = Vec::with_capacity(3);
            bytes.push(0xFD);
            bytes.extend_from_slice(&self.integer.to_le_bytes()[..2]);
            bytes
        } else if self.integer <= 0xFFFFFFFF {
            let mut bytes = Vec::with_capacity(5);
            bytes.push(0xFE);
            bytes.extend_from_slice(&self.integer.to_le_bytes()[..4]);
            bytes
        } else {
            let mut bytes = Vec::with_capacity(9);
            bytes.push(0xFF);
            bytes.extend_from_slice(&self.integer.to_le_bytes()[..8]);
            bytes
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(u64, usize), Box<dyn Error>> {
        let first_byte = bytes[0] as u64;
        let mut end_index = 0;
        if first_byte < 0xFD {
            return Result::Ok((first_byte as u64, 1));
        } else if first_byte == 0xFD {
            end_index = 3;
        } else if first_byte == 0xFE {
            end_index = 5;
        } else {
            end_index = 9;
        }
        let mut nbytes = [0 as u8; 8];
        for (i, byte) in bytes[1..end_index].iter().enumerate() {
            nbytes[i] = *byte;
        }
        Result::Ok((u64::from_le_bytes(nbytes), end_index))
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    fn test(number: u64, size: usize) {
        let vi = VariableInteger::new(number);
        assert_eq!(
            (number, size),
            VariableInteger::from_bytes(&vi.bytes()).unwrap()
        );
    }

    #[test]
    fn test_8() {
        test(0x42, 1);
    }

    #[test]
    fn test_16() {
        test(0xFAFE, 3);
    }

    #[test]
    fn test_32() {
        test(0xFAFBFCFD, 5);
    }

    #[test]
    fn test_64() {
        test(0xFAFBFCFDFEFF, 9);
    }
}
