use crate::{
    block_hash::BlockHash,
    serialize::{DynamicSized, Serialize, StaticSized},
    transaction_hash::TransactionHash,
    transaction_varuint::TransactionVarUint,
};

use sha3::{Digest, Sha3_256};

const HASH_SIZE: usize = 32;

#[derive(Clone)]
pub struct TransactionInput {
    pub block_hash: BlockHash,
    pub transaction_hash: TransactionHash,
    pub output_index: TransactionVarUint,
}

impl TransactionInput {
    pub fn new(
        block_hash: BlockHash,
        transaction_hash: TransactionHash,
        output_index: TransactionVarUint,
    ) -> Self {
        TransactionInput {
            block_hash,
            transaction_hash,
            output_index,
        }
    }

    pub fn hash(&self) -> [u8; HASH_SIZE] {
        let mut hash = [0u8; HASH_SIZE];
        let mut self_serialized = vec![0u8; self.serialized_len()];
        self.serialize_into(&mut self_serialized, &mut 0).unwrap();
        hash.copy_from_slice(Sha3_256::digest(&self_serialized).as_slice());
        hash
    }

    pub fn sign_hash(&self) -> Result<[u8; HASH_SIZE], String> {
        let mut self_serialized = vec![0u8; HASH_SIZE + self.output_index.serialized_len()];
        let mut i = 0;
        self.block_hash
            .serialize_into(&mut self_serialized, &mut i)?;
        self.transaction_hash
            .serialize_into(&mut self_serialized, &mut i)?;
        self.output_index
            .serialize_into(&mut self_serialized, &mut i)?;
        let mut hash = [0u8; HASH_SIZE];
        hash.copy_from_slice(Sha3_256::digest(&self_serialized).as_slice());
        Ok(hash)
    }
}

impl PartialEq for TransactionInput {
    fn eq(&self, other: &Self) -> bool {
        self.transaction_hash == other.transaction_hash && self.output_index == other.output_index
    }
}

impl Serialize for TransactionInput {
    fn from_serialized(data: &[u8], i: &mut usize) -> Result<Box<Self>, String> {
        let block_hash = *BlockHash::from_serialized(data, i)?;
        let transaction_hash = *TransactionHash::from_serialized(data, i)?;
        let output_index = *TransactionVarUint::from_serialized(data, i)?;
        Ok(Box::new(TransactionInput {
            block_hash,
            transaction_hash,
            output_index,
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
        self.block_hash.serialize_into(data, i)?;
        self.transaction_hash.serialize_into(data, i)?;
        self.output_index.serialize_into(data, i)?;
        Ok(())
    }
}

impl DynamicSized for TransactionInput {
    fn serialized_len(&self) -> usize {
        BlockHash::serialized_len()
            + TransactionHash::serialized_len()
            + self.output_index.serialized_len()
    }
}
