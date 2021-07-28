use crate::{
    block_hash::BlockHash,
    merkle_forest::{MerkleForest, HASH_SIZE},
    serialize::{DynamicSized, Serialize},
    transaction_input::TransactionInput,
    transaction_output::TransactionOutput,
    transaction_varuint::TransactionVarUint,
    transaction_version::TransactionVersion,
};
use secp256k1::{Message, Secp256k1, SecretKey, Signature};
use sha3::{Digest, Sha3_256};

pub const SECP256K1_SIG_LEN: usize = 64;

#[derive(Clone)]
pub struct Transaction {
    version: TransactionVersion,
    pub inputs: Vec<TransactionInput>,
    pub outputs: Vec<TransactionOutput>,
    pub signatures: Vec<Option<Signature>>,
    pub magic: TransactionVarUint,
}

impl Transaction {
    pub fn new(
        version: TransactionVersion,
        inputs: Vec<TransactionInput>,
        outputs: Vec<TransactionOutput>,
    ) -> Self {
        let signatures = vec![None; inputs.len()];
        Transaction {
            version,
            inputs,
            outputs,
            signatures,
            magic: TransactionVarUint::from(0),
        }
    }

    pub fn get_output(&self, index: &TransactionVarUint) -> TransactionOutput {
        self.outputs[index.get_value()].clone()
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
            digest_len += input.serialized_len();
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
            input.serialize_into(&mut digest, &mut i)?;
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
        match self.signatures[index] {
            Some(_) => Err(format!("Input at index {} already signed", index)),
            None => {
                let secp = Secp256k1::new();
                let message = Message::from_slice(&self.get_sign_hash()?).unwrap();
                self.signatures[index] = Some(secp.sign(&message, &sk));
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
        if self.signatures.len() == self.inputs.len() {
            for (i, input) in self.inputs.iter().enumerate() {
                match self.signatures[i] {
                    Some(s) => match merkle_forest.get_transactions(vec![input.transaction_hash]) {
                        Ok(tx) => {
                            let pk = &tx[0].get_output(&input.index).pk;
                            if let Err(e) = secp.verify(&trans_hash, &s, pk) {
                                return Err(format!(
                                    "Could not verify signature: {}",
                                    e.to_string()
                                ));
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
                        return Err(format!("Signature at index {} is not signed", i));
                    }
                }
            }
        } else {
            return Err(format!(
                "Signature count ({}) does not match input count ({})",
                self.signatures.len(),
                self.inputs.len()
            ));
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
        let version = *TransactionVersion::from_serialized(&data, i)?;
        let num_of_inputs = *TransactionVarUint::from_serialized(data, i)?;
        let mut inputs = Vec::new();
        for _ in 0..num_of_inputs.get_value() {
            inputs.push(*TransactionInput::from_serialized(&data, i)?);
        }
        let num_of_outputs = *TransactionVarUint::from_serialized(data, i)?;
        let mut outputs = Vec::new();
        for _ in 0..num_of_outputs.get_value() {
            outputs.push(*TransactionOutput::from_serialized(&data, i)?);
        }
        let num_of_signatures = *TransactionVarUint::from_serialized(data, i)?;
        let mut signatures = Vec::new();
        for _ in 0..num_of_signatures.get_value() {
            match Signature::from_compact(&data[*i..*i + SECP256K1_SIG_LEN]) {
                Ok(signature) => {
                    *i += signature.serialize_compact().len();
                    signatures.push(Some(signature));
                }
                Err(e) => {
                    return Err(format!(
                        "Could not load serialized signature: {}",
                        e.to_string()
                    ))
                }
            }
        }
        let magic = *TransactionVarUint::from_serialized(data, i)?;
        Ok(Box::new(Transaction {
            version,
            inputs,
            outputs,
            signatures,
            magic,
        }))
    }

    fn serialize_into(&self, mut data: &mut [u8], i: &mut usize) -> Result<(), String> {
        self.version.serialize_into(&mut data, i)?;
        TransactionVarUint::from(self.inputs.len()).serialize_into(data, i)?;
        for input in self.inputs.iter() {
            input.serialize_into(&mut data, i)?;
        }
        TransactionVarUint::from(self.outputs.len()).serialize_into(data, i)?;
        for output in self.outputs.iter() {
            output.serialize_into(&mut data, i)?;
        }
        TransactionVarUint::from(self.signatures.len()).serialize_into(data, i)?;
        for (index, signature) in self.signatures.iter().enumerate() {
            match signature {
                Some(s) => {
                    let compact_signature = s.serialize_compact();
                    data[*i..*i + compact_signature.len()].copy_from_slice(&compact_signature);
                    *i += compact_signature.len();
                }
                None => {
                    return Err(format!(
                        "Transaction input at index {} not yet signed",
                        index
                    ))
                }
            }
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
            + TransactionVarUint::from(self.signatures.len()).serialized_len()
            + self
                .inputs
                .iter()
                .fold(0usize, |sum, val| sum + val.serialized_len())
            + self
                .outputs
                .iter()
                .fold(0usize, |sum, val| sum + val.serialized_len())
            + self.signatures.len() * SECP256K1_SIG_LEN
            + self.magic.serialized_len()
    }
}
