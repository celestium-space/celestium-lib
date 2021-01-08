use crate::{
    serialize::{DynamicSized, Serialize},
    transaction::Transaction,
    transaction_output::TransactionOutput,
    transaction_varuint::TransactionVarUint,
};
use secp256k1::Signature;
use sha2::{Digest, Sha256};

const SECP256K1_SIG_LEN: usize = 64;
const HASH_SIZE: usize = 32;

#[derive(Clone)]
pub struct TransactionInput {
    pub tx: [u8; HASH_SIZE],
    pub index: TransactionVarUint,
    pub signature: Option<Signature>,
}

impl TransactionInput {
    pub fn from_transaction(transaction: Transaction, index: TransactionVarUint) -> Self {
        TransactionInput {
            tx: transaction.hash(),
            index,
            signature: None,
        }
    }

    pub fn hash(&self) -> [u8; HASH_SIZE] {
        let mut hash = [0u8; HASH_SIZE];
        let mut self_serialized = vec![0u8; self.serialized_len()];
        self.serialize_into(&mut self_serialized, &mut 0).unwrap();
        hash.copy_from_slice(Sha256::digest(&self_serialized).as_slice());
        hash
    }

    pub fn sign_hash(&self) -> [u8; HASH_SIZE] {
        let mut hash = [0u8; HASH_SIZE];
        let mut self_serialized = vec![0u8; HASH_SIZE + self.index.serialized_len()];
        self_serialized[0..HASH_SIZE].copy_from_slice(&self.tx);
        let mut i = HASH_SIZE;
        self.index
            .serialize_into(&mut self_serialized, &mut i)
            .unwrap();
        hash.copy_from_slice(Sha256::digest(&self_serialized).as_slice());
        hash
    }
}

impl PartialEq for TransactionInput {
    fn eq(&self, other: &Self) -> bool {
        self.tx == other.tx && self.index == other.index && self.signature == other.signature
    }
}

impl Serialize for TransactionInput {
    fn from_serialized(data: &[u8], i: &mut usize) -> Result<Box<Self>, String> {
        let mut tx = [0u8; HASH_SIZE];
        tx.copy_from_slice(&data[*i..*i + HASH_SIZE]);
        *i += HASH_SIZE;
        let index = *TransactionVarUint::from_serialized(data, i)?;
        match Signature::from_compact(&data[*i..*i + SECP256K1_SIG_LEN]) {
            Ok(signature) => {
                *i += signature.serialize_compact().len();
                Ok(Box::new(TransactionInput {
                    tx,
                    index,
                    signature: Some(signature),
                }))
            }
            Err(e) => Err(e.to_string()),
        }
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
        let pre_i = *i;
        data[*i..*i + HASH_SIZE].copy_from_slice(&self.tx);
        *i += HASH_SIZE;
        self.index.serialize_into(data, i)?;
        let signature = self.signature.unwrap_or_default();
        let compact_signature = signature.serialize_compact();
        data[*i..*i + compact_signature.len()].copy_from_slice(&compact_signature);
        *i += compact_signature.len();
        Ok(())
    }
}

impl DynamicSized for TransactionInput {
    fn serialized_len(&self) -> usize {
        HASH_SIZE + self.index.serialized_len() + SECP256K1_SIG_LEN
    }
}
