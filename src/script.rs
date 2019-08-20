use std::collections::HashMap;

use crate::crypto;
use crate::crypto::Hashable;
use crate::transaction::{Transaction, TxOutput};

#[derive(Debug, Clone)]
pub enum StackEntry {
    Array(Vec<u8>),
    Bool(bool),
    Number(i64),
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
    block_timestamp: u64,
}

pub struct ScriptResult {
    stack: Vec<StackEntry>,
    invalid: bool,
}

impl Script {
    fn op_push(&mut self) {
        println!("op_push");
        let size = self.code[self.pc];
        self.pc += 1;
        let mut array = Vec::with_capacity(size as usize);
        array.extend_from_slice(&self.code[self.pc..(self.pc + size as usize)]);
        self.stack.push(StackEntry::Array(array));
        self.pc += size as usize;
    }

    fn op_dup(&mut self) {
        println!("op_dup");
        let new = self.stack[self.stack.len() - 1].clone();
        self.stack.push(new);
        self.pc += 1;
    }

    fn op_hash160(&mut self) {
        println!("op_hash160");
        self.pc += 1;
        if let Some(StackEntry::Array(data)) = self.stack.pop() {
            let h = crypto::hash20(&data);
            self.stack.push(StackEntry::Array(h.to_vec()));
        } else {
            panic!("Invalid stack");
        }
    }

    fn op_equal(&mut self) {
        println!("op_equal");
        self.pc += 1;
        let x1 = self.stack.pop().unwrap();
        let x2 = self.stack.pop().unwrap();

        let to_add = match (x1, x2) {
            (StackEntry::Array(ref val1), StackEntry::Array(ref val2)) if val1 == val2 => {
                StackEntry::Bool(true)
            }
            (StackEntry::Bool(val1), StackEntry::Bool(val2)) if val1 == val2 => {
                StackEntry::Bool(true)
            }
            _ => StackEntry::Bool(false),
        };

        self.stack.push(to_add);
    }

    fn op_verify(&mut self) {
        println!("op_verify");
        self.pc += 1;
        let val = self.stack.pop().unwrap();

        self.transaction_invalid = match val {
            StackEntry::Array(ref vect) if vect.is_empty() => true,
            StackEntry::Bool(false) => true,
            _ => false,
        }
    }

    fn op_equalverify(&mut self) {
        println!("op_equalverify");
        // op_equal and op_verify both increment pc
        self.pc -= 1;
        self.op_equal();
        self.op_verify();
    }

    fn checksig(&self, pub_key_str: Vec<u8>, mut sig_str: Vec<u8>) -> bool {
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
        match crypto::check_signature(&pub_key_str, &sig_str, &crypto::hash32(&bytes)) {
            Ok(true) => true,
            _ => false,
        }
    }

    fn op_checkmultisigverify(&mut self) {
        println!("op_checkmultisigverify");
        self.pc -= 1;
        self.op_checkmultisig();
        self.op_verify();
    }

    fn op_checkmultisig(&mut self) {
        println!("op_checkmultisig");

        self.pc += 1;
        // The first entry represents the number of public keys
        if let StackEntry::Number(pubkeys_len) = self.stack.pop().unwrap() {
            if pubkeys_len <= 0 {
                panic!("pubkeys must be > 0");
            }

            let mut pubkeys = Vec::with_capacity(pubkeys_len as usize);
            let mut pubkeys_index = 0;
            for _ in 0..pubkeys_len {
                pubkeys.push(match self.stack.pop().unwrap() {
                    StackEntry::Array(bytes) => bytes,
                    _ => panic!("Wrong public key"),
                });
            }
            pubkeys.reverse();

            if let StackEntry::Number(sigs_len) = self.stack.pop().unwrap() {
                let mut sigs = Vec::new();
                for _ in 0..sigs_len {
                    sigs.push(match self.stack.pop().unwrap() {
                        StackEntry::Array(bytes) => bytes,
                        _ => panic!("Wrong signature"),
                    });
                }
                sigs.reverse();
                // A bug causes CHECKMULTISIG to consume one extra argument
                // whose contents were not checked in any way.
                //
                // Unfortunately this is a potential source of mutability,
                // so optionally verify it is exactly equal to zero prior
                // to removing it from the stack.
                let should_panic = match self.stack.pop().unwrap() {
                    StackEntry::Bool(false) => false,
                    StackEntry::Array(vector) => !vector.is_empty(),
                    _ => true,
                };

                if should_panic {
                    panic!("There should be an unused stack element.");
                }

                for i in 0..sigs_len {
                    while pubkeys_index < pubkeys_len {
                        if self.checksig(
                            sigs[i as usize].clone(),
                            pubkeys[pubkeys_index as usize].clone(),
                        ) {
                            pubkeys_index += 1;
                            break;
                        }
                        pubkeys_index += 1;
                    }
                    if pubkeys_index == pubkeys_len && i < sigs_len - 1 {
                        self.stack.push(StackEntry::Bool(false));
                        return;
                    }
                }

                self.stack.push(StackEntry::Bool(true));
            } else {
                panic!("Signatures number expected.");
            }
        } else {
            panic!("Public keys number expected.");
        }
    }

    fn op_checksig(&mut self) {
        println!("op_checksig");
        // Step 1
        if let StackEntry::Array(pub_key_str) = self.stack.pop().unwrap() {
            if let StackEntry::Array(sig_str) = self.stack.pop().unwrap() {
                self.stack
                    .push(StackEntry::Bool(self.checksig(pub_key_str, sig_str)));
            }
        }

        self.pc += 1;
    }

    fn op_checksigverify(&mut self) {
        println!("op_checksigverify");
        self.pc -= 1;
        self.op_checksig();
        self.op_verify();
    }

    fn op_true(&mut self) {
        println!("op_true");
        self.stack.push(StackEntry::Number(1));
        self.pc += 1;
    }

    fn op_false(&mut self) {
        println!("op_false");
        self.stack.push(StackEntry::Array(Vec::new()));
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
        self.op_map.insert(0xad, Script::op_checksigverify);
        self.op_map.insert(0x51, Script::op_true);
        self.op_map.insert(0xae, Script::op_checkmultisig);
        self.op_map.insert(0xaf, Script::op_checkmultisigverify);
        self.op_map.insert(0x00, Script::op_false);
    }

    pub fn new(
        tx_new: Box<Transaction>,
        input_index: usize,
        tx_prev_out: Box<TxOutput>,
        block_timestamp: u64,
    ) -> Self {
        let script_sig = (*(*tx_new).inputs[input_index]).sig();
        let pk_script = (*tx_prev_out).pubkey();
        let mut code = Vec::with_capacity(script_sig.len() + pk_script.len());
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
            block_timestamp,
        }
    }

    fn is_pay_to_script_hash(&self) -> bool {
        // We check that block timestamp is greater than 1333238400
        if self.block_timestamp < 1333238400 {
            return false;
        }

        let mut index = 0;
        // Check scriptPubKey
        // Assert scriptPubKey length
        if self.txout_pkscript.len() != 23 {
            return false;
        }
        let opcode = self.txout_pkscript[index];
        index += 1;
        // First op must be op_hash160
        if opcode != 0xa9 {
            return false;
        }
        // Next 20 bytes hash value
        let opcode = self.txout_pkscript[index];
        index += 1;
        if opcode != 20 {
            return false;
        }
        index += 20;
        // Then op_equal
        let opcode = self.txout_pkscript[index];
        index += 1;
        if opcode != 0x87 {
            return false;
        }

        true
    }

    pub fn exec(&mut self) -> ScriptResult {
        // Initialize execution
        self.build_op_map();

        self.stack.clear();
        self.pc = 0;
        loop {
            self.exec_next_instruction();
            if self.exec_is_finished() || self.transaction_invalid {
                break;
            }
        }

        if self.transaction_invalid || !self.is_pay_to_script_hash() {
            return ScriptResult {
                stack: self.stack.clone(),
                invalid: self.transaction_invalid,
            };
        }

        // Pay to script hash => Extended validation
        let script = self.pop_serialized_script().unwrap();
        self.code.clear();
        self.code.extend_from_slice(&self.txin_scriptsig);
        self.code.extend_from_slice(&script);

        // Reset stack
        self.pc = 0;
        self.stack.clear();

        loop {
            self.exec_next_instruction();
            if self.exec_is_finished() || self.transaction_invalid {
                break;
            }
        }

        return ScriptResult {
            stack: self.stack.clone(),
            invalid: self.transaction_invalid,
        };
    }

    fn pop_serialized_script(&mut self) -> Result<Vec<u8>, ()> {
        let mut index = 0;
        let txin_scriptsig_len = self.txin_scriptsig.len();
        let mut opcode = self.txin_scriptsig[index];
        let mut size = 0;
        while index < txin_scriptsig_len {
            opcode = self.txin_scriptsig[index];
            index += 1;
            // FIXME : Is it always the right size ?
            // Should take in account push ops, and maybe others...
            if opcode >= 0x01 && opcode <= 0x4b {
                size = opcode as usize;
            }
            index += size;
        }
        if index != txin_scriptsig_len {
            return Err(());
        }
        let start = index - size;
        let script = self.txin_scriptsig[start..].to_vec();
        let end = if start > 0 { start - 1 } else { start };
        self.txin_scriptsig = self.txin_scriptsig[0..end].to_vec();
        Ok(script)
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
        tx_new.add_input(
            [0 as u8; 32],
            0xffffffff,
            hex::decode("1234567890").unwrap(),
        );
        let input_index = 0;
        let tx_new_box = Box::new(tx_new);

        let mut tx_prev = Transaction::new();
        tx_prev.add_output(1, hex::decode("abcdef").unwrap());
        let tx_prev_out = tx_prev.outputs[0].clone();

        let script = Script::new(tx_new_box, input_index, tx_prev_out, 0);
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
        let mut script = Script::new(tx_new, input_index, tx_prev_out, 0);
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
        let mut script = Script::new(tx_new, input_index, tx_prev_out, 0);
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
        let mut script = Script::new(tx_new, input_index, tx_prev_out, 0);
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
        let mut script = Script::new(tx_new, input_index, tx_prev_out, 0);
        let result = script.exec();
        assert!(!result.invalid);
        assert_eq!(result.stack.len(), 1);
        if let StackEntry::Array(vect) = &result.stack[0] {
            assert_eq!(
                vect,
                &hex::decode("7bf35740091d766c45e3c052aa173fa4af80027d").unwrap()
            );
        } else {
            panic!();
        }
    }

    #[test]
    fn test_equal() {
        // Test with equal arrays of size 5
        let code = hex::decode("05010203040505010203040587").unwrap();
        let (tx_new, input_index, tx_prev_out) = get_script_parameters(code);
        let mut script = Script::new(tx_new, input_index, tx_prev_out, 0);
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
        let mut script = Script::new(tx_new, input_index, tx_prev_out, 0);
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
        let mut script = Script::new(tx_new, input_index, tx_prev_out, 0);
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
        let mut script = Script::new(tx_new, input_index, tx_prev_out, 0);
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
        let mut script = Script::new(tx_new, input_index, tx_prev_out, 0);
        let result = script.exec();
        assert!(result.invalid);
        assert!(result.stack.is_empty());

        let code = hex::decode("010101018769").unwrap();
        let (tx_new, input_index, tx_prev_out) = get_script_parameters(code);
        let mut script = Script::new(tx_new, input_index, tx_prev_out, 0);
        let result = script.exec();
        assert!(!result.invalid);
        assert!(result.stack.is_empty());
    }

    #[test]
    fn test_equalverify() {
        let code = hex::decode("0102010188").unwrap();
        let (tx_new, input_index, tx_prev_out) = get_script_parameters(code);
        let mut script = Script::new(tx_new, input_index, tx_prev_out, 0);
        let result = script.exec();
        assert!(result.invalid);
        assert!(result.stack.is_empty());

        let code = hex::decode("0101010188").unwrap();
        let (tx_new, input_index, tx_prev_out) = get_script_parameters(code);
        let mut script = Script::new(tx_new, input_index, tx_prev_out, 0);
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
        for (i, byte) in
            hex::decode("87a157f3fd88ac7907c05fc55e271dc4acdc5605d187d646604ca8c0e9382e03")
                .unwrap()
                .iter()
                .enumerate()
        {
            hash[31 - i] = *byte;
        }
        tx_new.add_input(hash, 0, scriptsig);
        tx_new.add_output(
            556_000_000,
            hex::decode("76a914c398efa9c392ba6013c5e04ee729755ef7f58b3288ac").unwrap(),
        );
        tx_new.add_output(
            4_444_000_000,
            hex::decode("76a914948c765a6914d43f2a7ac177da2c2f6b52de3d7c88ac").unwrap(),
        );

        // Verify the hash of the transaction
        assert_eq!(
            "fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4",
            hex::encode(tx_new.hash())
        );

        let input_index = 0;

        let mut tx_prev = Transaction::new();
        let pkscript = hex::decode("76a91471d7dd96d9edda09180fe9d57a477b5acc9cad1188ac").unwrap();

        tx_prev.add_output(5_000_000_000, pkscript);
        let tx_prev_out = tx_prev.outputs[0].clone();

        let mut script = Script::new(tx_new, input_index, tx_prev_out, 0);
        let result = script.exec();
        assert!(!result.invalid);
        assert_eq!(result.stack.len(), 1);
        match result.stack[0] {
            StackEntry::Bool(true) => (),
            _ => panic!(),
        }
    }

    #[test]
    /// The test is based on the inputs of transaction
    /// 5f87fb3a7491ef0a74003edd51de0a4533a354728f17140520da5e7df579d464
    fn test_checksig_2() {
        let mut tx_new = Box::new(Transaction::new());

        let mut hash = crypto::bytes_to_hash32(
            &hex::decode("41b02a6333272b9c5df83603ac91d0710730aee5bbdeeef4f95afc39018053db")
                .unwrap(),
        )
        .unwrap();
        let scriptsig = hex::decode("4830450220443e88089b0685c3b24ef78c28fd65dc98e7c473edbfa7e2324912252f0dd677022100e4d1b9f84c0e034d8dc0a556b2136b0257078e68e86d6313faad0ea95049f97001").unwrap();
        tx_new.add_input(hash, 0, scriptsig);

        let mut hash = crypto::bytes_to_hash32(
            &hex::decode("6a7d09bf1629bc5147e5adbcb6fac39de6616d2a281c905ae04b528ae95e416d")
                .unwrap(),
        )
        .unwrap();
        let scriptsig = hex::decode("483045022100d11686794cb7998dfdcdc46114b52d887bb37cc7830ee1208893759026b83c0002206bd00a793cf5b20d8d9d71a2d690ce882dc97a89010cb0b3b758b44944872cb401").unwrap();
        tx_new.add_input(hash, 0, scriptsig);

        tx_new.add_output(
            10_000_000_000,
            hex::decode("76a9148fe32b94a6760650409dab4f64252f3f07f8f33e88ac").unwrap(),
        );

        // Verify the hash of the transaction
        assert_eq!(
            "5f87fb3a7491ef0a74003edd51de0a4533a354728f17140520da5e7df579d464",
            hex::encode(tx_new.hash())
        );

        // Check first input
        let input_index = 0;

        let mut tx_prev = Transaction::new();
        let pkscript = hex::decode("4104bb24090e128506bc3c5335cb47ae254a3919c3619df8c780511cedb5837d2360ef6d7fbeeaace93f6e0b0dcf29515684843208744ad3292e4e32ad3b1b931892ac").unwrap();

        tx_prev.add_output(5_000_000_000, pkscript);
        let tx_prev_out = tx_prev.outputs[0].clone();

        let mut script = Script::new(tx_new.clone(), input_index, tx_prev_out, 0);
        let result = script.exec();
        assert!(!result.invalid);
        assert_eq!(result.stack.len(), 1);
        match result.stack[0] {
            StackEntry::Bool(true) => (),
            _ => panic!(),
        }

        // Check second input
        let input_index = 1;

        let mut tx_prev = Transaction::new();
        let pkscript = hex::decode("410421ca0ddad2cfae978d8863d391b068af9ed72dac32f3d4f2d9f3a09253483d0a283054a20fa9f230c1f5fd40f3df4669dd5e6a48f7dfe142f1be8df09383e072ac").unwrap();

        tx_prev.add_output(5_000_000_000, pkscript);
        let tx_prev_out = tx_prev.outputs[0].clone();

        let mut script = Script::new(tx_new, input_index, tx_prev_out, 0);
        let result = script.exec();
        assert!(!result.invalid);
        assert_eq!(result.stack.len(), 1);
        match result.stack[0] {
            StackEntry::Bool(true) => (),
            _ => panic!(),
        }
    }

    #[test]
    fn test_pay_to_script_hash() {
        let mut tx_new = Box::new(Transaction::new());

        tx_new.add_input(
            crypto::bytes_to_hash32(
                &hex::decode("9c08a4d78931342b37fd5f72900fb9983087e6f46c4a097d8a1f52c74e28eaf6")
                    .unwrap(),
            )
            .unwrap(),
            1,
            hex::decode(
                "255121029b6d2c97b8b7c718c325d7be3ac30f7c9d67651bce0c929f55ee77ce58efcf8451ae",
            )
            .unwrap(),
        );

        let mut tx_prev = Transaction::new();
        tx_prev.add_output(
            5_000_000_000,
            hex::decode("a91419a7d869032368fd1f1e26e5e73a4ad0e474960e87").unwrap(),
        );
        let tx_prev_out = tx_prev.outputs[0].clone();

        let mut script = Script::new(tx_new.clone(), 0, tx_prev_out, 0);
        let result = script.exec();
        assert!(!result.invalid);
        assert_eq!(result.stack.len(), 1);
        match result.stack[0] {
            StackEntry::Bool(true) => (),
            _ => panic!(),
        }
    }

    #[test]
    #[should_panic]
    fn test_pay_to_script_hash_invalid() {
        // The following transaction is not compliant with BIP16
        // https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki

        let mut tx_new = Box::new(Transaction::new());

        tx_new.add_input(
            crypto::bytes_to_hash32(
                &hex::decode("9c08a4d78931342b37fd5f72900fb9983087e6f46c4a097d8a1f52c74e28eaf6")
                    .unwrap(),
            )
            .unwrap(),
            1,
            hex::decode(
                "255121029b6d2c97b8b7c718c325d7be3ac30f7c9d67651bce0c929f55ee77ce58efcf8451ae",
            )
            .unwrap(),
        );

        let mut tx_prev = Transaction::new();
        tx_prev.add_output(
            5_000_000_000,
            hex::decode("a91419a7d869032368fd1f1e26e5e73a4ad0e474960e87").unwrap(),
        );
        let tx_prev_out = tx_prev.outputs[0].clone();

        let mut script = Script::new(tx_new.clone(), 0, tx_prev_out, 1333238400);
        let result = script.exec();
        assert!(!result.invalid);
        assert_eq!(result.stack.len(), 1);
        match result.stack[0] {
            StackEntry::Bool(true) => (),
            _ => panic!(),
        }
    }

    #[test]
    fn test_pay_to_script_hash_40eee() {
        let mut tx_new = Box::new(Transaction::new());

        tx_new.add_input(
            crypto::bytes_to_hash32(
                &hex::decode("40eee3ae1760e3a8532263678cdf64569e6ad06abc133af64f735e52562bccc8")
                    .unwrap(),
            )
            .unwrap(),
            0,
            hex::decode(
                "00483045022100ad0851c69dd756b45190b5a8e97cb4ac3c2b0fa2f2aae23aed6ca97ab33bf88302200b248593abc1259512793e7dea61036c601775ebb23640a0120b0dba2c34b79001455141042f90074d7a5bf30c72cf3a8dfd1381bdbd30407010e878f3a11269d5f74a58788505cdca22ea6eab7cfb40dc0e07aba200424ab0d79122a653ad0c7ec9896bdf51ae",
            )
            .unwrap(),
        );

        let mut tx_prev = Transaction::new();
        tx_prev.add_output(
            1000000,
            hex::decode("a914e9c3dd0c07aac76179ebc76a6c78d4d67c6c160a87").unwrap(),
        );
        let tx_prev_out = tx_prev.outputs[0].clone();

        let mut script = Script::new(tx_new.clone(), 0, tx_prev_out, 1333238400);
        let result = script.exec();
        assert!(!result.invalid);
        match result.stack.last().unwrap() {
            StackEntry::Bool(true) => (),
            _ => panic!(),
        }
    }
}
