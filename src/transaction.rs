use crate::transaction_value::TRANSACTION_ID_LEN;
use crate::{
    block_hash::BlockHash,
    serialize::{DynamicSized, Serialize, StaticSized},
    transaction_hash::TransactionHash,
    transaction_input::TransactionInput,
    transaction_output::TransactionOutput,
    transaction_varuint::TransactionVarUint,
    transaction_version::TransactionVersion,
    wallet::{OutputIndex, HASH_SIZE},
};
use indexmap::IndexMap;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey, Signature};
use sha3::{Digest, Sha3_256};
use std::collections::{HashMap, HashSet};

pub const SECP256K1_SIG_LEN: usize = 64;
pub const BASE_TRANSACTION_MESSAGE_LEN: usize = 33;

#[derive(Clone)]
pub struct Transaction {
    version: TransactionVersion,
    inputs: Vec<(TransactionInput, Option<Signature>)>,
    outputs: Vec<TransactionOutput>,
    pub magic: TransactionVarUint,
    is_base: bool,
}

// 2 (mig) + 3 (mig) -> 1 (mig) + 4 (dig)

impl Transaction {
    pub fn new(
        inputs: Vec<TransactionInput>,
        outputs: Vec<TransactionOutput>,
    ) -> Result<Self, String> {
        if inputs.is_empty() {
            return Err("Transactions must have at least 1 input".to_string());
        }
        Ok(Transaction {
            version: TransactionVersion::default(),
            inputs: inputs.into_iter().map(|input| (input, None)).collect(),
            outputs,
            magic: TransactionVarUint::from(0),
            is_base: false,
        })
    }

    pub fn new_coin_base_transaction(
        block_hash: BlockHash,
        message: [u8; BASE_TRANSACTION_MESSAGE_LEN],
        transaction_output: TransactionOutput,
    ) -> Result<Self, String> {
        let transaction_hash = *TransactionHash::from_serialized(&message, &mut 0).unwrap();
        let base_input = TransactionInput::new(
            block_hash,
            transaction_hash,
            TransactionVarUint::from(message[HASH_SIZE] as usize),
        );
        if transaction_output.value.is_coin_transfer() {
            Ok(Transaction {
                version: TransactionVersion::default(),
                inputs: vec![(base_input, None)],
                outputs: vec![transaction_output],
                magic: TransactionVarUint::from(0),
                is_base: true,
            })
        } else {
            Err("Trying to create coin base transaction which does not have coin value".to_string())
        }
    }

    pub fn new_id_base_transaction(
        block_hash: BlockHash,
        message: [u8; BASE_TRANSACTION_MESSAGE_LEN],
        transaction_output: TransactionOutput,
    ) -> Result<Self, String> {
        let transaction_hash = *TransactionHash::from_serialized(&message, &mut 0).unwrap();
        let base_input = TransactionInput::new(
            block_hash,
            transaction_hash,
            TransactionVarUint::from(message[HASH_SIZE] as usize),
        );
        if transaction_output.value.is_id_transfer() {
            Ok(Transaction {
                version: TransactionVersion::default(),
                inputs: vec![(base_input, None)],
                outputs: vec![transaction_output],
                magic: TransactionVarUint::from(0),
                is_base: true,
            })
        } else {
            Err("Trying to create id base transaction which does not have id value".to_string())
        }
    }

    pub fn get_id(&self) -> Result<[u8; TRANSACTION_ID_LEN], String> {
        if self.is_id_base_transaction() {
            Ok(self.outputs[0].value.get_id().unwrap())
        } else {
            Err("Can only get ID from ID base transactions".to_string())
        }
    }

    pub fn is_base_transaction(&self) -> bool {
        self.is_base
    }

    pub fn is_coin_base_transaction(&self) -> bool {
        self.is_base_transaction() && self.outputs[0].value.is_coin_transfer()
    }

    pub fn is_id_base_transaction(&self) -> bool {
        self.is_base_transaction() && self.outputs[0].value.is_id_transfer()
    }

    pub fn count_inputs(&self) -> usize {
        self.inputs.len()
    }

    pub fn count_outputs(&self) -> usize {
        self.outputs.len()
    }

    pub fn get_output(&self, index: &TransactionVarUint) -> TransactionOutput {
        self.outputs[index.get_value()].clone()
    }

    pub fn get_outputs(&self) -> Vec<TransactionOutput> {
        self.outputs.clone()
    }

    pub fn get_inputs(&self) -> Vec<TransactionInput> {
        self.inputs.iter().map(|(t, _)| t.clone()).collect()
    }

    pub fn get_base_transaction_message(
        &self,
    ) -> Result<[u8; BASE_TRANSACTION_MESSAGE_LEN], String> {
        if self.is_id_base_transaction() {
            let mut base_transaction_message = [0u8; BASE_TRANSACTION_MESSAGE_LEN];
            self.inputs[0]
                .0
                .transaction_hash
                .serialize_into(&mut base_transaction_message, &mut 0)?;
            base_transaction_message[HASH_SIZE] = self.inputs[0].0.output_index.get_value() as u8;
            Ok(base_transaction_message)
        } else {
            Err("Transaction is not ID base transaction".to_string())
        }
    }

    pub fn magic_serialized_len(&self) -> usize {
        self.magic.serialized_len()
    }

    pub fn hash(&self) -> Result<TransactionHash, String> {
        let non_magic_hash = self.get_non_magic_hash()?;
        let mut digest = vec![0u8; TransactionHash::serialized_len() + self.magic.serialized_len()];
        let mut i = 0;
        non_magic_hash.serialize_into(&mut digest, &mut i)?;
        self.magic.serialize_into(&mut digest, &mut i)?;
        Ok(*TransactionHash::from_serialized(&Sha3_256::digest(&digest), &mut 0).unwrap())
    }

    pub fn get_total_fee(&self) -> u128 {
        let mut total_fee = 0;
        for output in self.outputs.iter() {
            if output.value.is_coin_transfer() {
                total_fee += output.value.get_fee().unwrap();
            }
        }
        total_fee
    }

    pub fn get_total_output_value(&self) -> u128 {
        let mut total_value = 0;
        for output in self.outputs.iter() {
            if output.value.is_coin_transfer() {
                total_value += output.value.get_value().unwrap();
            }
        }
        total_value
    }

    fn get_sign_hash(&self) -> Result<[u8; HASH_SIZE], String> {
        let mut digest_len = self.version.serialized_len()
            + TransactionVarUint::from(self.inputs.len()).serialized_len()
            + TransactionVarUint::from(self.outputs.len()).serialized_len();
        for input in &self.inputs {
            digest_len += input.0.serialized_len();
        }
        for output in &self.outputs {
            digest_len += output.serialized_len();
        }
        let mut digest = vec![0u8; digest_len];
        let mut i = 0;
        self.version.serialize_into(&mut digest, &mut i)?;
        TransactionVarUint::from(self.inputs.len()).serialize_into(&mut digest, &mut i)?;
        for input in &self.inputs {
            input.0.serialize_into(&mut digest, &mut i)?;
        }
        TransactionVarUint::from(self.outputs.len()).serialize_into(&mut digest, &mut i)?;
        for output in &self.outputs {
            output.serialize_into(&mut digest, &mut i)?;
        }

        let mut hash = [0u8; HASH_SIZE];
        hash.copy_from_slice(&Sha3_256::digest(&digest));
        Ok(hash)
    }

    pub fn sign(&mut self, sk: SecretKey, index: usize) -> Result<bool, String> {
        let last_index = self.inputs.len() - 1;
        if index > last_index {
            return Err(format!(
                "Index out of range, expected max {} got {}",
                last_index, index
            ));
        }
        match self.inputs[index].1 {
            Some(_) => Err(format!("Input at index {} already signed", index)),
            None => {
                let secp = Secp256k1::new();
                let sign_hash = &self.get_sign_hash()?;
                let message = Message::from_slice(sign_hash).unwrap();
                self.inputs[index].1 = Some(secp.sign(&message, &sk));
                Ok(true)
            }
        }
    }

    pub fn get_non_magic_hash(&self) -> Result<TransactionHash, String> {
        let mut serialized_transaction = vec![0u8; self.serialized_len()];
        self.serialize_into(&mut serialized_transaction, &mut 0)?;
        let mut non_magic_hash_slice = [0u8; HASH_SIZE];
        non_magic_hash_slice.copy_from_slice(
            &Sha3_256::digest(
                &serialized_transaction
                    [..serialized_transaction.len() - self.magic.serialized_len()],
            )
            .to_vec(),
        );
        Ok(TransactionHash::from(non_magic_hash_slice))
    }

    pub fn verify_signatures(
        &self,
        my_block_transactions: &IndexMap<TransactionHash, Transaction>,
        on_chain_transactions: &HashMap<BlockHash, IndexMap<TransactionHash, Transaction>>,
    ) -> Result<Vec<PublicKey>, String> {
        if self.is_base_transaction() {
            return Ok(Vec::new());
        }
        let secp = Secp256k1::new();
        let trans_hash = Message::from_slice(&self.get_sign_hash()?).unwrap();
        let mut pks = Vec::new();
        for (i, (input, signature)) in self.inputs.iter().enumerate() {
            match signature {
                Some(s) => {
                    let transactions = if input.block_hash == BlockHash::from([0u8; HASH_SIZE]) {
                        my_block_transactions
                    } else {
                        match on_chain_transactions.get(&input.block_hash) {
                            Some(t) => t,
                            None => return Err(format!("Block {} not found", input.block_hash)),
                        }
                    };

                    match transactions.get(&input.transaction_hash) {
                        Some(tx) => {
                            let pk = tx.get_output(&input.output_index).pk;
                            if let Err(e) = secp.verify(&trans_hash, s, &pk) {
                                return Err(format!(
                                    "Could not verify signature: {}",
                                    e.to_string()
                                ));
                            }
                            pks.push(pk);
                        }
                        None => {
                            return Err(format!(
                            "Could not find input transaction {} on block {} referenced by input",
                            input.transaction_hash, input.block_hash
                        ))
                        }
                    }
                }
                None => {
                    return Err(format!("Input at index {} is not signed", i));
                }
            }
        }
        Ok(pks)
    }

    pub fn contains_enough_work(&self) -> Result<bool, String> {
        Ok(TransactionHash::contains_enough_work(&self.hash()?.hash()))
    }

    pub fn verify_transaction(
        &self,
        my_block_transactions: &IndexMap<TransactionHash, Transaction>,
        on_chain_transactions: &HashMap<BlockHash, IndexMap<TransactionHash, Transaction>>,
        unspent_outputs: &HashMap<
            PublicKey,
            HashMap<(BlockHash, TransactionHash, OutputIndex), TransactionOutput>,
        >,
    ) -> Result<Vec<PublicKey>, String> {
        if !self.contains_enough_work()? {
            return Err(format!(
                "Transaction ({}) does not contain enough work",
                self.hash()?
            ));
        }

        let pks = self.verify_signatures(my_block_transactions, on_chain_transactions)?;

        // Check if transaction is balanced (input value == output value)
        if !self.is_id_base_transaction() {
            let mut transaction_ids = HashSet::new();
            let mut total_dust = 0;
            for output in self.outputs.iter() {
                if output.value.is_coin_transfer() {
                    total_dust += output.value.get_value()?;
                } else {
                    transaction_ids.insert(output.value.get_id()?);
                }
            }

            for (input, _) in self.inputs.iter() {
                let key = &(
                    input.block_hash.clone(),
                    input.transaction_hash.clone(),
                    input.output_index.clone(),
                );
                let mut output_found = false;

                for pk in pks.iter() {
                    if let Some(pk_unspent_outputs) = unspent_outputs.get(&pk) {
                        if let Some(output) = pk_unspent_outputs.get(key) {
                            if output.value.is_coin_transfer() {
                                total_dust -= output.value.get_value()?;
                            } else if !transaction_ids.remove(&output.value.get_id()?) {
                                return Err(format!("Transaction trying to spent output {} on transaction {} on block {}, which has not been declared as an input", key.2, key.1, key.0));
                            }
                            output_found = true;
                            break;
                        }
                    }
                }

                if !output_found {
                    return Err(format!(
                        "Input {} on transaction {} on block {} does not refer to known unspent output",
                        key.2,
                        key.1,
                        key.0
                    ));
                }
            }
            if total_dust != 0 {
                return Err(format!(
                    "Transaction value is unbalanced (i->{}->o)",
                    total_dust
                ));
            }
            if !transaction_ids.is_empty() {
                return Err(format!(
                    "Transaction has {} unspent inputs",
                    transaction_ids.len()
                ));
            }
        }
        Ok(pks)
    }
}

impl PartialEq for Transaction {
    fn eq(&self, other: &Self) -> bool {
        self.hash() == other.hash()
    }
}

impl Serialize for Transaction {
    fn from_serialized(data: &[u8], i: &mut usize) -> Result<Box<Self>, String> {
        let version = *TransactionVersion::from_serialized(data, i)?;
        let num_of_inputs = *TransactionVarUint::from_serialized(data, i)?;
        let mut inputs = Vec::new();
        let mut is_base = false;
        let mut num_of_inputs_value = num_of_inputs.get_value();
        if num_of_inputs_value == 0 {
            is_base = true;
            num_of_inputs_value = 1;
        }
        for _ in 0..num_of_inputs_value {
            inputs.push((
                *TransactionInput::from_serialized(&data, i)?,
                match is_base {
                    false => match Signature::from_compact(&data[*i..*i + SECP256K1_SIG_LEN]) {
                        Ok(signature) => {
                            *i += signature.serialize_compact().len();
                            Some(signature)
                        }
                        Err(e) => {
                            return Err(format!(
                                "Could not load serialized signature: {}",
                                e.to_string()
                            ))
                        }
                    },
                    true => None,
                },
            ));
        }

        let num_of_outputs = *TransactionVarUint::from_serialized(data, i)?;
        if num_of_outputs.get_value() < 1 {
            return Err("Encountered transaction with no outputs, must be at least 1".to_string());
        }
        if is_base && num_of_outputs.get_value() != 1 {
            return Err(format!(
                "Encountered base transaction with {} outputs, must be exactly 1",
                num_of_outputs.get_value()
            ));
        }
        let mut outputs = Vec::new();
        for _ in 0..num_of_outputs.get_value() {
            outputs.push(*TransactionOutput::from_serialized(&data, i)?);
        }
        let magic = *TransactionVarUint::from_serialized(data, i)?;
        Ok(Box::new(Transaction {
            version,
            inputs,
            outputs,
            magic,
            is_base,
        }))
    }

    fn serialize_into(&self, mut data: &mut [u8], i: &mut usize) -> Result<(), String> {
        self.version.serialize_into(&mut data, i)?;

        if self.is_base_transaction() {
            data[*i] = 0;
            *i += 1;
        } else {
            TransactionVarUint::from(self.inputs.len()).serialize_into(data, i)?;
        }

        for (input, signature) in self.inputs.iter() {
            input.serialize_into(&mut data, i)?;
            if !self.is_base_transaction() {
                match signature {
                    Some(s) => {
                        let compact_signature = s.serialize_compact();
                        data[*i..*i + compact_signature.len()].copy_from_slice(&compact_signature);
                        *i += compact_signature.len();
                    }
                    None => {
                        data[*i..*i + 64].copy_from_slice(&[0u8; 64]);
                        *i += 64;
                    }
                }
            }
        }

        TransactionVarUint::from(self.outputs.len()).serialize_into(data, i)?;
        for output in self.outputs.iter() {
            output.serialize_into(&mut data, i)?;
        }

        self.magic.serialize_into(data, i)?;
        Ok(())
    }
}

impl DynamicSized for Transaction {
    fn serialized_len(&self) -> usize {
        self.version.serialized_len()
            + TransactionVarUint::from(self.inputs.len()).serialized_len()
            + TransactionVarUint::from(self.outputs.len()).serialized_len()
            + if self.is_base_transaction() {
                HASH_SIZE + BASE_TRANSACTION_MESSAGE_LEN
            } else {
                self.inputs.iter().fold(0, |sum, (input, _)| {
                    sum + input.serialized_len() + SECP256K1_SIG_LEN
                })
            }
            + self
                .outputs
                .iter()
                .fold(0, |sum, val| sum + val.serialized_len())
            + self.magic.serialized_len()
    }
}
