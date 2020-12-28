use crate::{
    serialize::{DynamicSized, Serialize},
    transaction_value::TransactionValue,
};
use secp256k1::PublicKey;
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct TransactionOutput {
    value: TransactionValue,
    pub pk: PublicKey,
}

impl TransactionOutput {
    pub fn new(value: TransactionValue, pk: PublicKey) -> Self {
        TransactionOutput { value, pk }
    }

    pub fn get_value_clone(&self) -> TransactionValue {
        self.value.clone()
    }

    pub fn hash(&self) -> [u8; 32] {
        let mut hash = [0u8; 32];
        let mut self_serialized = vec![0u8; self.serialized_len()];
        self.serialize_into(&mut self_serialized, &mut 0).unwrap();
        hash.copy_from_slice(Sha256::digest(&self_serialized).as_slice());
        hash
    }
}

impl Serialize for TransactionOutput {
    fn from_serialized(
        _data: &[u8],
        _i: &mut usize,
        _users: &mut std::collections::HashMap<PublicKey, crate::user::User>,
    ) -> Result<Box<Self>, String> {
        todo!()
    }

    fn serialize_into(&self, _data: &mut [u8], _i: &mut usize) -> Result<usize, String> {
        todo!()
    }
}

impl DynamicSized for TransactionOutput {
    fn serialized_len(&self) -> usize {
        todo!()
    }
}
