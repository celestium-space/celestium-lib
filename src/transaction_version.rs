use crate::{
    merkle_forest::HASH_SIZE,
    serialize::{DynamicSized, Serialize},
};
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct TransactionVersion {
    pub value: [u8; 1],
}

impl TransactionVersion {
    pub fn default() -> Self {
        TransactionVersion { value: [0] }
    }

    pub fn hash(&self) -> [u8; HASH_SIZE] {
        let mut hash = [0u8; HASH_SIZE];
        hash.copy_from_slice(&Sha256::digest(&self.value));
        hash
    }
}

impl Serialize for TransactionVersion {
    fn from_serialized(
        data: &[u8],
        i: &mut usize,
        _: &mut std::collections::HashMap<secp256k1::PublicKey, crate::user::User>,
    ) -> Result<Box<Self>, String> {
        if data[*i] != 0 {
            Err(format!("Expected transaction version 0 found {}", data[*i]))
        } else {
            *i += 1;
            Ok(Box::new(TransactionVersion {
                value: [data[*i - 1]],
            }))
        }
    }

    fn serialize_into(&self, data: &mut [u8], i: &mut usize) -> Result<usize, String> {
        data[*i] = self.value[0];
        *i += 1;
        Ok(1)
    }
}

impl DynamicSized for TransactionVersion {
    fn serialized_len(&self) -> usize {
        1
    }
}
