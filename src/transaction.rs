use crate::{
    merkle_forest::HASH_SIZE,
    serialize::{DynamicSized, Serialize},
    transaction_input::TransactionInput,
    transaction_output::TransactionOutput,
    transaction_varuint::TransactionVarUint,
    transaction_version::TransactionVersion,
};
use secp256k1::{Message, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct Transaction {
    version: TransactionVersion,
    pub inputs: Vec<TransactionInput>,
    pub outputs: Vec<TransactionOutput>,
}

impl Transaction {
    pub fn new(
        version: TransactionVersion,
        inputs: Vec<TransactionInput>,
        outputs: Vec<TransactionOutput>,
    ) -> Self {
        Transaction {
            version,
            inputs,
            outputs,
        }
    }

    pub fn get_output(&self, index: &TransactionVarUint) -> TransactionOutput {
        self.outputs[index.get_value()].clone()
    }

    pub fn hash(&self) -> [u8; 32] {
        let mut data = vec![0; self.serialized_len()];
        self.serialize_into(&mut data, &mut 0).unwrap();
        let mut hash = [0; 32];
        hash.copy_from_slice(&Sha256::digest(&data));
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

    fn get_sign_hash(&self) -> [u8; HASH_SIZE] {
        let mut digest = vec![0u8; HASH_SIZE * (1 + self.outputs.len() + self.inputs.len())];
        let mut i = 0;
        digest[i..i + HASH_SIZE].copy_from_slice(&self.version.hash());
        i += HASH_SIZE;
        for input in self.inputs.iter() {
            digest[i..i + HASH_SIZE].copy_from_slice(&input.sign_hash());
            i += HASH_SIZE;
        }
        for output in self.outputs.iter() {
            digest[i..i + HASH_SIZE].copy_from_slice(&output.hash());
            i += HASH_SIZE;
        }
        let mut hash = [0u8; HASH_SIZE];
        hash.copy_from_slice(&Sha256::digest(&digest));
        hash
    }

    pub fn sign(&mut self, sk: SecretKey, index: usize) -> Result<bool, String> {
        let last_index = self.inputs.len() - 1;
        if index > last_index {
            return Err(format!(
                "Index out of range, expected max {} got {}",
                last_index, index
            ));
        }
        match self.inputs[index].signature {
            Some(_) => Err(format!("Input at index {} already signed", index)),
            None => {
                let secp = Secp256k1::new();
                let message =
                    Message::from_slice(Sha256::digest(&self.get_sign_hash()).as_slice()).unwrap();
                self.inputs[index].signature = Some(secp.sign(&message, &sk));
                Ok(true)
            }
        }
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
        Ok(Box::new(Transaction {
            version,
            inputs,
            outputs,
        }))
    }

    fn serialize_into(&self, mut data: &mut [u8], i: &mut usize) -> Result<(), String> {
        self.version.serialize_into(&mut data, i)?;
        data[*i] = self.inputs.len() as u8;
        *i += 1;
        for input in self.inputs.iter() {
            input.serialize_into(&mut data, i)?;
        }
        data[*i] = self.outputs.len() as u8;
        *i += 1;
        for output in self.outputs.iter() {
            output.serialize_into(&mut data, i)?;
        }
        Ok(())
    }
}

impl DynamicSized for Transaction {
    fn serialized_len(&self) -> usize {
        self.version.serialized_len()
            + TransactionVarUint::from(self.inputs.len()).serialized_len()
            + TransactionVarUint::from(self.outputs.len()).serialized_len()
            + self
                .inputs
                .iter()
                .fold(0usize, |sum, val| sum + val.serialized_len())
            + self
                .outputs
                .iter()
                .fold(0usize, |sum, val| sum + val.serialized_len())
    }
}
