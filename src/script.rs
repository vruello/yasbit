
use std::collections::HashMap;

use crate::crypto;
use crate::transaction::Transaction;

#[derive(Debug, Clone)]
pub enum StackEntry {
    Byte(u8),
    Array(Vec<u8>),
    Bool(bool)
}

pub struct Script {
    content: Vec<u8>,
    stack: Vec<StackEntry>,
    pc: usize,
    op_map: HashMap<u8, fn(&mut Script) -> ()>,
    transaction_invalid: bool,
    transaction: Box<Transaction>,
    input_index: usize,
}

impl Script {
    fn op_push(&mut self) {
        let size = self.content[self.pc];
        self.pc += 1;
        let mut array = Vec::with_capacity(size as usize);
        array.extend_from_slice(&self.content[self.pc..(self.pc + size as usize)]);
        self.stack.push(StackEntry::Array(array));
        self.pc += size as usize;
    }

    fn op_dup(&mut self) {
        let new = self.stack[self.stack.len() - 1].clone();
        self.stack.push(new);
        self.pc += 1;
    }

    fn op_hash160(&mut self) {
        self.pc += 1;
        if let Some(StackEntry::Array(data)) = self.stack.pop() {
            let h = crypto::hash20(&data);
            self.stack.push(StackEntry::Array(h.to_vec()));
        } else {
            panic!("Invalid stack");
        } 
    }

    fn op_equal(&mut self) {
        self.pc += 1;
        let x1 = self.stack.pop().unwrap();
        let x2 = self.stack.pop().unwrap();

        let to_add = match(x1, x2) {
            (StackEntry::Byte(val1), StackEntry::Byte(val2)) if val1 == val2 => StackEntry::Bool(true),
            (StackEntry::Array(ref val1), StackEntry::Array(ref val2)) if val1 == val2 => StackEntry::Bool(true),
            (StackEntry::Bool(val1), StackEntry::Bool(val2)) if val1 == val2 => StackEntry::Bool(true),
            _ => StackEntry::Bool(false)
        };

        self.stack.push(to_add);
    }

    fn op_verify(&mut self) {
        self.pc += 1;
        let val = self.stack.pop().unwrap();

        self.transaction_invalid = match val {
            StackEntry::Byte(x) if x == 0 => true,
            StackEntry::Array(ref vect) if vect.is_empty() => true,
            StackEntry::Bool(false) => true,
            _ => false
        }
    }

    fn op_equalverify(&mut self) {
        // op_equal and op_verify both increment pc
        self.pc -= 1;
        self.op_equal();
        self.op_verify();
    }

    fn op_checksig(&mut self) {
        // Step 1
        if let StackEntry::Array(pub_key_str) = self.stack.pop().unwrap() {
            if let StackEntry::Array(mut sig_str) = self.stack.pop().unwrap() {
                // Step 2
                // FIXME we assume that there is no OP_CODESEPARATOR for now
                let sub_script = self.content.clone();
                
                // FIXME Step 3/4

                // Step 5
                let hashtype = sig_str.pop().unwrap() as u32;

                // Step 6
                let mut tx_copy = self.transaction.clone();
                
                // Step 7
                for input in tx_copy.inputs.iter_mut() {
                    let tx_input = &mut input.script_sig;
                    tx_input.clear();
                }

                // Step 8
                let input = &mut tx_copy.inputs[self.input_index];
                input.script_sig.extend_from_slice(sub_script.as_slice());

                // Step 9
                let mut bytes = tx_copy.bytes();
                bytes.extend_from_slice(&hashtype.to_le_bytes());
                
                // Step 10
                let to_push = match crypto::check_signature(
                    &pub_key_str, &sig_str, crypto::hash32(&bytes)) {
                    Ok(true) => StackEntry::Bool(true),
                    _ => StackEntry::Bool(false)
                };
                self.stack.push(to_push);
            }
        }
    } 

    fn exec_next_instruction(&mut self) {
        let opcode = self.content[self.pc];
        if let Some(func) = self.op_map.get(&opcode) {
            func(self);
        } else if opcode >= 0x01 && opcode <= 0x4b {
            self.op_push();
        } else {
            panic!("Invalid opcode");
        }
    }

    fn exec_is_finished(&self) -> bool {
        self.content.len() == self.pc
    }

    pub fn build_op_map(&mut self) {
        self.op_map.insert(0x76, Script::op_dup);
        self.op_map.insert(0xa9, Script::op_hash160);
        self.op_map.insert(0x87, Script::op_equal);
        self.op_map.insert(0x69, Script::op_verify);
        self.op_map.insert(0x88, Script::op_equalverify);
        self.op_map.insert(0xad, Script::op_checksig);
    }

    pub fn new(content: &Vec<u8>, transaction: Box<Transaction>) -> Self {
        Script {
            content: content.clone(),
            stack: Vec::new(),
            pc: 0,
            op_map: HashMap::new(),
            transaction_invalid: false,
            transaction,
            input_index: 0
        }
    }

    pub fn exec(&mut self) -> Vec<StackEntry> {
        // Initialize execution
        self.stack.clear();
        self.pc = 0;
        self.build_op_map();

        loop {
            self.exec_next_instruction();
            if self.exec_is_finished() {
                break;
            }
        }

        self.stack.clone()
    }

    pub fn transaction_invalid(&self) -> bool {
        self.transaction_invalid
    }
}


#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_push() {
        let code = hex::decode("4930460221009805aa00cb6f80ca984584d4ca40f637fc948e3dbe159ea5c4eb6941bf4eb763022100e1cc0852d3f6eb87839edca1f90169088ed3502d8cde2f495840acac69eefc9801").unwrap();
        let mut script = Script::new(&code, Box::new(Transaction::new()));
        let stack = script.exec();
        assert_eq!(stack.len(), 1);
        if let StackEntry::Array(vect) = &stack[0] {
            assert_eq!(vect, &hex::decode("30460221009805aa00cb6f80ca984584d4ca40f637fc948e3dbe159ea5c4eb6941bf4eb763022100e1cc0852d3f6eb87839edca1f90169088ed3502d8cde2f495840acac69eefc9801").unwrap());
        } else {
            panic!();
        }

        let code = hex::decode("4930460221009805aa00cb6f80ca984584d4ca40f637fc948e3dbe159ea5c4eb6941bf4eb763022100e1cc0852d3f6eb87839edca1f90169088ed3502d8cde2f495840acac69eefc9801410486477e6a23cb25c9a99f0c467c6fc86197e718ebfd41d1aef7cc3cbd75197c1f1aaba985b22b366a0729ccb8aa38277809d6d218cf4077ac9f29a953b5435222").unwrap();
        let mut script = Script::new(&code, Box::new(Transaction::new()));
        let stack = script.exec();
        assert_eq!(stack.len(), 2);
        if let StackEntry::Array(vect) = &stack[0] {
            assert_eq!(vect, &hex::decode("30460221009805aa00cb6f80ca984584d4ca40f637fc948e3dbe159ea5c4eb6941bf4eb763022100e1cc0852d3f6eb87839edca1f90169088ed3502d8cde2f495840acac69eefc9801").unwrap());
        } else {
            panic!();
        }
        if let StackEntry::Array(vect) = &stack[1] {
            assert_eq!(vect, &hex::decode("0486477e6a23cb25c9a99f0c467c6fc86197e718ebfd41d1aef7cc3cbd75197c1f1aaba985b22b366a0729ccb8aa38277809d6d218cf4077ac9f29a953b5435222").unwrap());
        } else {
            panic!();
        }
    }

    #[test]
    fn test_dup() {
        let code = hex::decode("4930460221009805aa00cb6f80ca984584d4ca40f637fc948e3dbe159ea5c4eb6941bf4eb763022100e1cc0852d3f6eb87839edca1f90169088ed3502d8cde2f495840acac69eefc980176").unwrap();
        let mut script = Script::new(&code, Box::new(Transaction::new()));
        let stack = script.exec();
        assert_eq!(stack.len(), 2);
        if let StackEntry::Array(vect) = &stack[0] {
            assert_eq!(vect, &hex::decode("30460221009805aa00cb6f80ca984584d4ca40f637fc948e3dbe159ea5c4eb6941bf4eb763022100e1cc0852d3f6eb87839edca1f90169088ed3502d8cde2f495840acac69eefc9801").unwrap());
        } else {
            panic!();
        }
        if let StackEntry::Array(vect) = &stack[1] {
            assert_eq!(vect, &hex::decode("30460221009805aa00cb6f80ca984584d4ca40f637fc948e3dbe159ea5c4eb6941bf4eb763022100e1cc0852d3f6eb87839edca1f90169088ed3502d8cde2f495840acac69eefc9801").unwrap());
        } else {
            panic!();
        }
    }

    #[test]
    fn test_hash160() {
        let code = hex::decode("056261626172a9").unwrap();
        let mut script = Script::new(&code, Box::new(Transaction::new()));
        let stack = script.exec();
        assert_eq!(stack.len(), 1);
        if let StackEntry::Array(vect) = &stack[0] {
            assert_eq!(vect, &hex::decode("7bf35740091d766c45e3c052aa173fa4af80027d").unwrap());
        } else {
            panic!();
        }
    }

    #[test]
    fn test_equal() {
        // Test with equal arrays of size 5
        let code = hex::decode("05010203040505010203040587").unwrap();
        let mut script = Script::new(&code, Box::new(Transaction::new()));
        let stack = script.exec();
        assert_eq!(stack.len(), 1);
        if let StackEntry::Bool(value) = &stack[0] {
            assert_eq!(*value, true);
        } else {
            panic!();
        }
        // Test with different arrays of size 5
        let code = hex::decode("05010203040505010101010187").unwrap();
        let mut script = Script::new(&code, Box::new(Transaction::new()));
        let stack = script.exec();
        assert_eq!(stack.len(), 1);
        if let StackEntry::Bool(value) = &stack[0] {
            assert_eq!(*value, false);
        } else {
            panic!();
        }
        // Test with booleans from equal 
        let code = hex::decode("0101010187010101018787").unwrap();
        let mut script = Script::new(&code, Box::new(Transaction::new()));
        let stack = script.exec();
        assert_eq!(stack.len(), 1);
        if let StackEntry::Bool(value) = &stack[0] {
            assert_eq!(*value, true);
        } else {
            panic!();
        }
        // Test with booleans from equal 
        let code = hex::decode("0102010187010101018787").unwrap();
        let mut script = Script::new(&code, Box::new(Transaction::new()));
        let stack = script.exec();
        assert_eq!(stack.len(), 1);
        if let StackEntry::Bool(value) = &stack[0] {
            assert_eq!(*value, false);
        } else {
            panic!();
        }
    }

    #[test]
    fn test_verify() {
        let code = hex::decode("010101028769").unwrap();
        let mut script = Script::new(&code, Box::new(Transaction::new()));
        let stack = script.exec();
        assert!(stack.is_empty());
        assert!(script.transaction_invalid);
        
        let code = hex::decode("010101018769").unwrap();
        let mut script = Script::new(&code, Box::new(Transaction::new()));
        let stack = script.exec();
        assert!(stack.is_empty());
        assert!(!script.transaction_invalid);
    }

    #[test]
    fn test_equalverify() {
        let code = hex::decode("0102010188").unwrap();
        let mut script = Script::new(&code, Box::new(Transaction::new()));
        let stack = script.exec();
        assert!(stack.is_empty());
        assert!(script.transaction_invalid);
        
        let code = hex::decode("0101010188").unwrap();
        let mut script = Script::new(&code, Box::new(Transaction::new()));
        let stack = script.exec();
        assert!(stack.is_empty());
        assert!(!script.transaction_invalid);
    }

    #[test]
    fn test_checksig() {
        // TODO
        panic!("Test not implemented");
    }
}
