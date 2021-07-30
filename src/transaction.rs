use crate::{
    block_hash::BlockHash,
    merkle_forest::{MerkleForest, HASH_SIZE},
    serialize::{DynamicSized, Serialize},
    transaction_input::TransactionInput,
    transaction_output::TransactionOutput,
    transaction_value::TransactionValue,
    transaction_varuint::TransactionVarUint,
    transaction_version::TransactionVersion,
};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey, Signature};
use sha3::{Digest, Sha3_256};

pub const SECP256K1_SIG_LEN: usize = 64;

#[derive(Clone)]
pub struct Transaction {
    version: TransactionVersion,
    base_transaction_message: Option<[u8; 64]>,
    inputs: Vec<(TransactionInput, Option<Signature>)>,
    outputs: Vec<TransactionOutput>,
    magic: TransactionVarUint,
}

impl Transaction {
    pub fn new(
        inputs: Vec<TransactionInput>,
        outputs: Vec<TransactionOutput>,
    ) -> Result<Self, String> {
        if inputs.is_empty() {
            return Err("Normal transactions must have at least 1 input".to_string());
        }
        Ok(Transaction {
            version: TransactionVersion::default(),
            base_transaction_message: None,
            inputs: inputs.into_iter().map(|input| (input, None)).collect(),
            outputs,
            magic: TransactionVarUint::from(0),
        })
    }

    pub fn new_nft_base_transaction(nft: [u8; 64], pk: PublicKey) -> Self {
        let mut hash = [0u8; HASH_SIZE];
        hash.copy_from_slice(&Sha3_256::digest(&nft));
        let transaction_output =
            TransactionOutput::new(TransactionValue::new_id_transfer(hash).unwrap(), pk);
        Transaction::new_coin_base_transaction(nft, transaction_output)
    }

    pub fn new_coin_base_transaction(
        message: [u8; 64],
        transaction_output: TransactionOutput,
    ) -> Self {
        Transaction {
            version: TransactionVersion::default(),
            base_transaction_message: Some(message),
            inputs: vec![],
            outputs: vec![transaction_output],
            magic: TransactionVarUint::from(0),
        }
    }

    pub fn is_base_transaction(&self) -> bool {
        self.inputs.is_empty() && self.outputs.len() == 1
    }

    pub fn is_coin_base_transaction(&self) -> bool {
        self.is_base_transaction() && self.outputs[0].value.is_coin_transfer()
    }

    pub fn count_inputs(&self) -> usize {
        self.inputs.len()
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

    pub fn magic_serialized_len(&self) -> usize {
        self.magic.serialized_len()
    }

    pub fn hash(&self) -> [u8; 32] {
        let mut data = vec![0; self.serialized_len()];
        self.serialize_into(&mut data, &mut 0).unwrap();
        let mut hash = [0; 32];
        hash.copy_from_slice(&Sha3_256::digest(&data));
        hash
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
        TransactionVarUint::from(self.outputs.len()).serialize_into(&mut digest, &mut i)?;
        for input in &self.inputs {
            input.0.serialize_into(&mut digest, &mut i)?;
        }
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
                let message = Message::from_slice(&self.get_sign_hash()?).unwrap();
                self.inputs[index].1 = Some(secp.sign(&message, &sk));
                Ok(true)
            }
        }
    }

    pub fn contains_enough_work(&self) -> bool {
        let mut serialized_transaction = vec![0u8; self.serialized_len()];
        match self.serialize_into(&mut serialized_transaction, &mut 0) {
            Ok(_) => {
                let hash = Sha3_256::digest(&serialized_transaction).to_vec();
                BlockHash::contains_enough_work(&hash)
            }
            Err(_) => false,
        }
    }

    // pub fn verify_content(&self) -> Result<(), String> {
    //     let mut input_value = 0;
    //     for input in self.inputs{
    //         input.
    //     }
    // }

    pub fn verify_signatures(
        &self,
        merkle_forest: &MerkleForest<Transaction>,
    ) -> Result<(), String> {
        let secp = Secp256k1::new();
        let trans_hash = Message::from_slice(&self.get_sign_hash()?).unwrap();
        for (i, (input, signature)) in self.inputs.iter().enumerate() {
            match signature {
                Some(s) => match merkle_forest.get_transactions(vec![input.transaction_hash]) {
                    Ok(tx) => {
                        let pk = &tx[0].get_output(&input.index).pk;
                        if let Err(e) = secp.verify(&trans_hash, &s, pk) {
                            return Err(format!("Could not verify signature: {}", e.to_string()));
                        }
                    }
                    Err(_) => {
                        return Err(format!(
                            "Could not find input transaction '{:x?}' referenced by input",
                            input.transaction_hash
                        ))
                    }
                },
                None => {
                    return Err(format!("Input at index {} is not signed", i));
                }
            }
        }
        Ok(())
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
        let mut binary_nft = None;
        let mut inputs = Vec::new();
        if num_of_inputs.get_value() == 0 {
            let mut binary_nft_data = [0u8; 64];
            binary_nft_data.copy_from_slice(&data[*i..*i + 64]);
            binary_nft = Some(binary_nft_data);
            *i += 64;
        } else {
            for _ in 0..num_of_inputs.get_value() {
                inputs.push((
                    *TransactionInput::from_serialized(&data, i)?,
                    match Signature::from_compact(&data[*i..*i + SECP256K1_SIG_LEN]) {
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
                ));
            }
        }
        let num_of_outputs = *TransactionVarUint::from_serialized(data, i)?;
        if num_of_inputs.get_value() == 0 && num_of_outputs.get_value() != 1 {
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
            base_transaction_message: binary_nft,
            inputs,
            outputs,
            magic,
        }))
    }

    fn serialize_into(&self, mut data: &mut [u8], i: &mut usize) -> Result<(), String> {
        self.version.serialize_into(&mut data, i)?;
        TransactionVarUint::from(self.inputs.len()).serialize_into(data, i)?;
        match self.base_transaction_message {
            Some(message) => {
                data[*i..*i + 64].copy_from_slice(&message);
                *i += 64;
            }
            None => {
                for (index, (input, signature)) in self.inputs.iter().enumerate() {
                    match signature {
                        Some(s) => {
                            input.serialize_into(&mut data, i)?;
                            let compact_signature = s.serialize_compact();
                            data[*i..*i + compact_signature.len()]
                                .copy_from_slice(&compact_signature);
                            *i += compact_signature.len();
                        }
                        None => return Err(format!("Input at index {} not yet signed", index)),
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
        let input_len = if self.is_base_transaction() {
            64
        } else {
            self.inputs.iter().fold(0usize, |sum, (input, _)| {
                sum + input.serialized_len() + SECP256K1_SIG_LEN
            })
        };
        self.version.serialized_len()
            + TransactionVarUint::from(self.inputs.len()).serialized_len()
            + TransactionVarUint::from(self.outputs.len()).serialized_len()
            + input_len
            + self
                .outputs
                .iter()
                .fold(0usize, |sum, val| sum + val.serialized_len())
            + self.magic.serialized_len()
    }
}
