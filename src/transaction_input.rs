use crate::{
    serialize::{DynamicSized, Serialize},
    transaction_varuint::TransactionVarUint,
};

use sha3::{Digest, Sha3_256};

const HASH_SIZE: usize = 32;

#[derive(Clone)]
pub struct TransactionInput {
    pub block_hash: [u8; HASH_SIZE],
    pub transaction_hash: [u8; HASH_SIZE],
    pub index: TransactionVarUint,
}

impl TransactionInput {
    pub fn new(
        block_hash: [u8; HASH_SIZE],
        transaction_hash: [u8; HASH_SIZE],
        index: TransactionVarUint,
    ) -> Self {
        TransactionInput {
            block_hash,
            transaction_hash,
            index,
        }
    }

    pub fn hash(&self) -> [u8; HASH_SIZE] {
        let mut hash = [0u8; HASH_SIZE];
        let mut self_serialized = vec![0u8; self.serialized_len()];
        self.serialize_into(&mut self_serialized, &mut 0).unwrap();
        hash.copy_from_slice(Sha3_256::digest(&self_serialized).as_slice());
        hash
    }

    pub fn sign_hash(&self) -> [u8; HASH_SIZE] {
        let mut self_serialized = vec![0u8; HASH_SIZE + self.index.serialized_len()];
        self_serialized[0..HASH_SIZE].copy_from_slice(&self.block_hash);
        self_serialized[0..HASH_SIZE].copy_from_slice(&self.transaction_hash);
        self.index
            .serialize_into(&mut self_serialized, &mut (HASH_SIZE * 2))
            .unwrap();
        let mut hash = [0u8; HASH_SIZE];
        hash.copy_from_slice(Sha3_256::digest(&self_serialized).as_slice());
        hash
    }
}

impl PartialEq for TransactionInput {
    fn eq(&self, other: &Self) -> bool {
        self.transaction_hash == other.transaction_hash && self.index == other.index
    }
}

impl Serialize for TransactionInput {
    fn from_serialized(data: &[u8], i: &mut usize) -> Result<Box<Self>, String> {
        let mut block_hash = [0u8; HASH_SIZE];
        block_hash.copy_from_slice(&data[*i..*i + HASH_SIZE]);
        *i += HASH_SIZE;
        let mut transaction_hash = [0u8; HASH_SIZE];
        transaction_hash.copy_from_slice(&data[*i..*i + HASH_SIZE]);
        *i += HASH_SIZE;
        let index = *TransactionVarUint::from_serialized(data, i)?;
        Ok(Box::new(TransactionInput {
            block_hash,
            transaction_hash,
            index,
        }))
    }

    fn serialize_into(&self, data: &mut [u8], i: &mut usize) -> Result<(), String> {
        let bytes_left = data.len() - *i;
        if bytes_left < self.serialized_len() {
            return Err(format!(
                "Too few bytes left for serializing transaction input, expected at least {} got {}",
                self.serialized_len(),
                bytes_left
            ));
        }
        data[*i..*i + HASH_SIZE].copy_from_slice(&self.block_hash);
        *i += HASH_SIZE;
        data[*i..*i + HASH_SIZE].copy_from_slice(&self.transaction_hash);
        *i += HASH_SIZE;
        self.index.serialize_into(data, i)?;
        Ok(())
    }
}

impl DynamicSized for TransactionInput {
    fn serialized_len(&self) -> usize {
        HASH_SIZE * 2 + self.index.serialized_len()
    }
}
