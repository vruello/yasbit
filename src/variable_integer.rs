
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
}
