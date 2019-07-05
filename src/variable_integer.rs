use std::fmt;
use std::error::Error;

#[derive(Debug, Clone)]
struct ArrayTooLargeError();

impl fmt::Display for ArrayTooLargeError{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "array length must not be larger than 9.")
    }
}

impl Error for ArrayTooLargeError {}

pub struct VariableInteger {
    integer: u64
}

/// This is the implementation of the Variable Integer Scheme used in BTC
/// https://en.bitcoin.it/wiki/Protocol_specification#Variable_length_integer
impl VariableInteger {
    pub fn new(integer:u64) -> Self {
        VariableInteger {
            integer
        }
    }

    pub fn bytes(&self) -> Vec<u8> {
        if self.integer < 0xFD {
            vec![self.integer as u8]
        }
        else if self.integer <= 0xFFFF {
            let mut bytes = Vec::with_capacity(3);
            bytes.push(0xFD);
            bytes.extend_from_slice(&self.integer.to_le_bytes()[..2]);
            bytes
        }
        else if self.integer <= 0xFFFFFFFF {
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

    pub fn from_bytes(bytes: &[u8]) -> Result<u64, Box<dyn Error>> {
        if bytes.len() > 9 {
            return Result::Err(Box::new(ArrayTooLargeError()));
        }
        let first_byte = bytes[0] as u64;
        if first_byte < 0xFD {
            Result::Ok(first_byte)
        } else {
            let mut nbytes = [0; 8];
            for (i, byte) in bytes[1..].iter().enumerate() {
                nbytes[i] = *byte;
            }
            Result::Ok(u64::from_le_bytes(nbytes))
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    fn test(number: u64) {
        let vi = VariableInteger::new(number);
        assert_eq!(number, VariableInteger::from_bytes(&vi.bytes()).unwrap());
    }

    #[test]
    fn test_8() {
        test(0x42);
    }

    #[test]
    fn test_16() {
        test(0xFAFE);
    }

    #[test]
    fn test_32() {
        test(0xFAFBFCFD);
    }

    #[test]
    fn test_64() {
        test(0xFAFBFCFDFEFF);
    }

    #[test]
    #[should_panic]
    fn test_invalid_array() {
        let arr = [0 as u8; 10];
        VariableInteger::from_bytes(&arr).unwrap();
    }
}
