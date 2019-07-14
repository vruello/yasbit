
use std::collections::HashMap;

use crate::crypto;
use crate::crypto::Hashable;
use crate::transaction::{Transaction, TxOutput};

#[derive(Debug, Clone)]
pub enum StackEntry {
    Array(Vec<u8>),
    Bool(bool)
}

pub struct Script {
    code: Vec<u8>,
    txin_scriptsig: Vec<u8>,
    txout_pkscript: Vec<u8>,
    stack: Vec<StackEntry>,
    pc: usize,
    op_map: HashMap<u8, fn(&mut Script) -> ()>,
    transaction: Box<Transaction>,
    transaction_invalid: bool,
    input_index: usize,
}

pub struct ScriptResult {
    stack: Vec<StackEntry>,
    invalid: bool
}

impl Script {
    fn op_push(&mut self) {
        let size = self.code[self.pc];
        self.pc += 1;
        let mut array = Vec::with_capacity(size as usize);
        array.extend_from_slice(&self.code[self.pc..(self.pc + size as usize)]);
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
                let sub_script = self.txout_pkscript.clone();
                
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

        self.pc += 1;
    } 

    fn exec_next_instruction(&mut self) {
        let opcode = self.code[self.pc];
        if let Some(func) = self.op_map.get(&opcode) {
            func(self);
        } else if opcode >= 0x01 && opcode <= 0x4b {
            self.op_push();
        } else {
            panic!("Invalid opcode {}", hex::encode([opcode]));
        }
    }

    fn exec_is_finished(&self) -> bool {
        self.code.len() == self.pc
    }

    pub fn build_op_map(&mut self) {
        self.op_map.insert(0x76, Script::op_dup);
        self.op_map.insert(0xa9, Script::op_hash160);
        self.op_map.insert(0x87, Script::op_equal);
        self.op_map.insert(0x69, Script::op_verify);
        self.op_map.insert(0x88, Script::op_equalverify);
        self.op_map.insert(0xac, Script::op_checksig);
    }

    pub fn new(tx_new: Box<Transaction>, input_index: usize, tx_prev_out: Box<TxOutput>) -> Self {
        let script_sig = (*(*tx_new).inputs[input_index]).sig();
        let pk_script = (*tx_prev_out).pubkey();
        let mut code = Vec::with_capacity(
            script_sig.len() +
            pk_script.len());
        code.extend_from_slice(script_sig.as_slice());
        code.extend_from_slice(pk_script.as_slice());

        Script {
            code: code,
            txin_scriptsig: script_sig,
            txout_pkscript: pk_script,
            stack: Vec::new(),
            pc: 0,
            op_map: HashMap::new(),
            transaction: tx_new,
            transaction_invalid: false,
            input_index,
        }
    }

    pub fn exec(&mut self) -> ScriptResult {
        // Initialize execution
        self.stack.clear();
        self.pc = 0;
        self.build_op_map();

        loop {
            self.exec_next_instruction();
            if self.exec_is_finished() || self.transaction_invalid {
                break;
            }
        }

        ScriptResult {
            stack: self.stack.clone(),
            invalid: self.transaction_invalid
        }
    }
}


#[cfg(test)]
mod tests {

    use super::*;

    fn get_script_parameters(code: Vec<u8>) -> (Box<Transaction>, usize, Box<TxOutput>) {
        let mut tx_new = Box::new(Transaction::new());
        tx_new.add_input([0 as u8; 32], 0xffffffff, code);
        let input_index = 0;

        let mut tx_prev = Transaction::new();
        tx_prev.add_output(1, vec![]);
        let tx_prev_out = tx_prev.outputs[0].clone();

        (tx_new, input_index, tx_prev_out)
    }

    #[test]
    fn test_script_struct() {
        let mut tx_new = Transaction::new();
        tx_new.add_input([0 as u8; 32], 0xffffffff, hex::decode("1234567890").unwrap());
        let input_index = 0;
        let tx_new_box = Box::new(tx_new);

        let mut tx_prev = Transaction::new();
        tx_prev.add_output(1, hex::decode("abcdef").unwrap());
        let tx_prev_out = tx_prev.outputs[0].clone();

        let script = Script::new(tx_new_box, input_index, tx_prev_out);
        assert_eq!(script.code, hex::decode("1234567890abcdef").unwrap());
        assert_eq!(script.txin_scriptsig, hex::decode("1234567890").unwrap());
        assert_eq!(script.txout_pkscript, hex::decode("abcdef").unwrap());
        assert!(script.stack.is_empty());
        assert_eq!(script.pc, 0);
        assert!(!script.transaction_invalid);
        assert_eq!(script.input_index, input_index);
    }

    #[test]
    fn test_push() {
        let code = hex::decode("4930460221009805aa00cb6f80ca984584d4ca40f637fc948e3dbe159ea5c4eb6941bf4eb763022100e1cc0852d3f6eb87839edca1f90169088ed3502d8cde2f495840acac69eefc9801").unwrap();
        let (tx_new, input_index, tx_prev_out) = get_script_parameters(code);
        let mut script = Script::new(tx_new, input_index, tx_prev_out);
        let result = script.exec();
        assert!(!result.invalid);
        assert_eq!(result.stack.len(), 1);
        if let StackEntry::Array(vect) = &result.stack[0] {
            assert_eq!(vect, &hex::decode("30460221009805aa00cb6f80ca984584d4ca40f637fc948e3dbe159ea5c4eb6941bf4eb763022100e1cc0852d3f6eb87839edca1f90169088ed3502d8cde2f495840acac69eefc9801").unwrap());
        } else {
            panic!();
        }

        let code = hex::decode("4930460221009805aa00cb6f80ca984584d4ca40f637fc948e3dbe159ea5c4eb6941bf4eb763022100e1cc0852d3f6eb87839edca1f90169088ed3502d8cde2f495840acac69eefc9801410486477e6a23cb25c9a99f0c467c6fc86197e718ebfd41d1aef7cc3cbd75197c1f1aaba985b22b366a0729ccb8aa38277809d6d218cf4077ac9f29a953b5435222").unwrap();
        let (tx_new, input_index, tx_prev_out) = get_script_parameters(code);
        let mut script = Script::new(tx_new, input_index, tx_prev_out);
        let result = script.exec();
        assert_eq!(result.stack.len(), 2);
        if let StackEntry::Array(vect) = &result.stack[0] {
            assert_eq!(vect, &hex::decode("30460221009805aa00cb6f80ca984584d4ca40f637fc948e3dbe159ea5c4eb6941bf4eb763022100e1cc0852d3f6eb87839edca1f90169088ed3502d8cde2f495840acac69eefc9801").unwrap());
        } else {
            panic!();
        }
        if let StackEntry::Array(vect) = &result.stack[1] {
            assert_eq!(vect, &hex::decode("0486477e6a23cb25c9a99f0c467c6fc86197e718ebfd41d1aef7cc3cbd75197c1f1aaba985b22b366a0729ccb8aa38277809d6d218cf4077ac9f29a953b5435222").unwrap());
        } else {
            panic!();
        }
    }

    #[test]
    fn test_dup() {
        let code = hex::decode("4930460221009805aa00cb6f80ca984584d4ca40f637fc948e3dbe159ea5c4eb6941bf4eb763022100e1cc0852d3f6eb87839edca1f90169088ed3502d8cde2f495840acac69eefc980176").unwrap();
        let (tx_new, input_index, tx_prev_out) = get_script_parameters(code);
        let mut script = Script::new(tx_new, input_index, tx_prev_out);
        let result = script.exec();
        assert!(!result.invalid);
        assert_eq!(result.stack.len(), 2);
        if let StackEntry::Array(vect) = &result.stack[0] {
            assert_eq!(vect, &hex::decode("30460221009805aa00cb6f80ca984584d4ca40f637fc948e3dbe159ea5c4eb6941bf4eb763022100e1cc0852d3f6eb87839edca1f90169088ed3502d8cde2f495840acac69eefc9801").unwrap());
        } else {
            panic!();
        }
        if let StackEntry::Array(vect) = &result.stack[1] {
            assert_eq!(vect, &hex::decode("30460221009805aa00cb6f80ca984584d4ca40f637fc948e3dbe159ea5c4eb6941bf4eb763022100e1cc0852d3f6eb87839edca1f90169088ed3502d8cde2f495840acac69eefc9801").unwrap());
        } else {
            panic!();
        }
    }

    #[test]
    fn test_hash160() {
        let code = hex::decode("056261626172a9").unwrap();
        let (tx_new, input_index, tx_prev_out) = get_script_parameters(code);
        let mut script = Script::new(tx_new, input_index, tx_prev_out);
        let result = script.exec();
        assert!(!result.invalid);
        assert_eq!(result.stack.len(), 1);
        if let StackEntry::Array(vect) = &result.stack[0] {
            assert_eq!(vect, &hex::decode("7bf35740091d766c45e3c052aa173fa4af80027d").unwrap());
        } else {
            panic!();
        }
    }

    #[test]
    fn test_equal() {
        // Test with equal arrays of size 5
        let code = hex::decode("05010203040505010203040587").unwrap();
        let (tx_new, input_index, tx_prev_out) = get_script_parameters(code);
        let mut script = Script::new(tx_new, input_index, tx_prev_out);
        let result = script.exec();
        assert!(!result.invalid);
        assert_eq!(result.stack.len(), 1);
        if let StackEntry::Bool(value) = &result.stack[0] {
            assert_eq!(*value, true);
        } else {
            panic!();
        }
        // Test with different arrays of size 5
        let code = hex::decode("05010203040505010101010187").unwrap();
        let (tx_new, input_index, tx_prev_out) = get_script_parameters(code);
        let mut script = Script::new(tx_new, input_index, tx_prev_out);
        let result = script.exec();
        assert!(!result.invalid);
        assert_eq!(result.stack.len(), 1);
        if let StackEntry::Bool(value) = &result.stack[0] {
            assert_eq!(*value, false);
        } else {
            panic!();
        }
        // Test with booleans from equal 
        let code = hex::decode("0101010187010101018787").unwrap();
        let (tx_new, input_index, tx_prev_out) = get_script_parameters(code);
        let mut script = Script::new(tx_new, input_index, tx_prev_out);
        let result = script.exec();
        assert!(!result.invalid);
        assert_eq!(result.stack.len(), 1);
        if let StackEntry::Bool(value) = &result.stack[0] {
            assert_eq!(*value, true);
        } else {
            panic!();
        }
        // Test with booleans from equal 
        let code = hex::decode("0102010187010101018787").unwrap();
        let (tx_new, input_index, tx_prev_out) = get_script_parameters(code);
        let mut script = Script::new(tx_new, input_index, tx_prev_out);
        let result = script.exec();
        assert!(!result.invalid);
        assert_eq!(result.stack.len(), 1);
        if let StackEntry::Bool(value) = &result.stack[0] {
            assert_eq!(*value, false);
        } else {
            panic!();
        }
    }

    #[test]
    fn test_verify() {
        let code = hex::decode("010101028769").unwrap();
        let (tx_new, input_index, tx_prev_out) = get_script_parameters(code);
        let mut script = Script::new(tx_new, input_index, tx_prev_out);
        let result = script.exec();
        assert!(result.invalid);
        assert!(result.stack.is_empty());
        
        let code = hex::decode("010101018769").unwrap();
        let (tx_new, input_index, tx_prev_out) = get_script_parameters(code);
        let mut script = Script::new(tx_new, input_index, tx_prev_out);
        let result = script.exec();
        assert!(!result.invalid);
        assert!(result.stack.is_empty());
    }

    #[test]
    fn test_equalverify() {
        let code = hex::decode("0102010188").unwrap();
        let (tx_new, input_index, tx_prev_out) = get_script_parameters(code);
        let mut script = Script::new(tx_new, input_index, tx_prev_out);
        let result = script.exec();
        assert!(result.invalid);
        assert!(result.stack.is_empty());
        
        let code = hex::decode("0101010188").unwrap();
        let (tx_new, input_index, tx_prev_out) = get_script_parameters(code);
        let mut script = Script::new(tx_new, input_index, tx_prev_out);
        let result = script.exec();
        assert!(!result.invalid);
        assert!(result.stack.is_empty());
    }

    #[test]
    /// The test is based on the second input of transaction
    /// fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4
    fn test_checksig_1() {
        let mut tx_new = Box::new(Transaction::new());

        let scriptsig = hex::decode("493046022100c352d3dd993a981beba4a63ad15c209275ca9470abfcd57da93b58e4eb5dce82022100840792bc1f456062819f15d33ee7055cf7b5ee1af1ebcc6028d9cdb1c3af7748014104f46db5e9d61a9dc27b8d64ad23e7383a4e6ca164593c2527c038c0857eb67ee8e825dca65046b82c9331586c82e0fd1f633f25f87c161bc6f8a630121df2b3d3").unwrap();

        let mut hash = [0 as u8; 32];
        for (i, byte) in hex::decode("87a157f3fd88ac7907c05fc55e271dc4acdc5605d187d646604ca8c0e9382e03").unwrap().iter().enumerate() {
            hash[31 - i] = *byte;
        }
        tx_new.add_input(hash, 0, scriptsig);
        tx_new.add_output(556_000_000, hex::decode("76a914c398efa9c392ba6013c5e04ee729755ef7f58b3288ac").unwrap());
        tx_new.add_output(4_444_000_000, hex::decode("76a914948c765a6914d43f2a7ac177da2c2f6b52de3d7c88ac").unwrap());

        // Verify the hash of the transaction
        assert_eq!("fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4", hex::encode(tx_new.hash()));

        let input_index = 0;

        let mut tx_prev = Transaction::new();
        let pkscript = hex::decode("76a91471d7dd96d9edda09180fe9d57a477b5acc9cad1188ac").unwrap();

        tx_prev.add_output(5_000_000_000, pkscript);
        let tx_prev_out = tx_prev.outputs[0].clone();

        let mut script = Script::new(tx_new, input_index, tx_prev_out);
        let result = script.exec();
        assert!(!result.invalid);
        assert_eq!(result.stack.len(), 1);
        match result.stack[0] {
            StackEntry::Bool(true) => (),
            _ => panic!()
        }
    }

    #[test]
    /// The test is based on the inputs of transaction
    /// 5f87fb3a7491ef0a74003edd51de0a4533a354728f17140520da5e7df579d464
    fn test_checksig_2() {
        let mut tx_new = Box::new(Transaction::new());

        let mut hash = [0 as u8; 32];
        for (i, byte) in hex::decode("41b02a6333272b9c5df83603ac91d0710730aee5bbdeeef4f95afc39018053db").unwrap().iter().enumerate() {
            hash[31 - i] = *byte;
        }
        let scriptsig = hex::decode("4830450220443e88089b0685c3b24ef78c28fd65dc98e7c473edbfa7e2324912252f0dd677022100e4d1b9f84c0e034d8dc0a556b2136b0257078e68e86d6313faad0ea95049f97001").unwrap();
        tx_new.add_input(hash, 0, scriptsig);

        let mut hash = [0 as u8; 32];
        for (i, byte) in hex::decode("6a7d09bf1629bc5147e5adbcb6fac39de6616d2a281c905ae04b528ae95e416d").unwrap().iter().enumerate() {
            hash[31 - i] = *byte;
        }
        let scriptsig = hex::decode("483045022100d11686794cb7998dfdcdc46114b52d887bb37cc7830ee1208893759026b83c0002206bd00a793cf5b20d8d9d71a2d690ce882dc97a89010cb0b3b758b44944872cb401").unwrap();
        tx_new.add_input(hash, 0, scriptsig);


        tx_new.add_output(10_000_000_000, hex::decode("76a9148fe32b94a6760650409dab4f64252f3f07f8f33e88ac").unwrap());

        // Verify the hash of the transaction
        assert_eq!("5f87fb3a7491ef0a74003edd51de0a4533a354728f17140520da5e7df579d464", hex::encode(tx_new.hash()));

        // Check first input
        let input_index = 0;

        let mut tx_prev = Transaction::new();
        let pkscript = hex::decode("4104bb24090e128506bc3c5335cb47ae254a3919c3619df8c780511cedb5837d2360ef6d7fbeeaace93f6e0b0dcf29515684843208744ad3292e4e32ad3b1b931892ac").unwrap();

        tx_prev.add_output(5_000_000_000, pkscript);
        let tx_prev_out = tx_prev.outputs[0].clone();

        let mut script = Script::new(tx_new.clone(), input_index, tx_prev_out);
        let result = script.exec();
        assert!(!result.invalid);
        assert_eq!(result.stack.len(), 1);
        match result.stack[0] {
            StackEntry::Bool(true) => (),
            _ => panic!()
        }

        // Check second input
        let input_index = 1;

        let mut tx_prev = Transaction::new();
        let pkscript = hex::decode("410421ca0ddad2cfae978d8863d391b068af9ed72dac32f3d4f2d9f3a09253483d0a283054a20fa9f230c1f5fd40f3df4669dd5e6a48f7dfe142f1be8df09383e072ac").unwrap();

        tx_prev.add_output(5_000_000_000, pkscript);
        let tx_prev_out = tx_prev.outputs[0].clone();

        let mut script = Script::new(tx_new, input_index, tx_prev_out);
        let result = script.exec();
        assert!(!result.invalid);
        assert_eq!(result.stack.len(), 1);
        match result.stack[0] {
            StackEntry::Bool(true) => (),
            _ => panic!()
        }
    }
}
