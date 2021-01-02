use crate::{
    serialize::{DynamicSized, Serialize, StaticSized},
    transaction_value::TransactionValue,
};
use secp256k1::PublicKey;
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct TransactionOutput {
    pub value: TransactionValue,
    pub pk: PublicKey,
}

impl TransactionOutput {
    pub fn new(value: TransactionValue, pk: PublicKey) -> Self {
        TransactionOutput { value, pk }
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
        println!("TransactionOutput from_serialized");
        todo!()
    }

    fn serialize_into(&self, data: &mut [u8], i: &mut usize) -> Result<usize, String> {
        let pre_i = *i;
        self.value.serialize_into(data, i)?;
        self.pk.serialize_into(data, i)?;
        Ok(*i - pre_i)
    }
}

impl DynamicSized for TransactionOutput {
    fn serialized_len(&self) -> usize {
        self.value.serialized_len() + PublicKey::serialized_len()
    }
}
