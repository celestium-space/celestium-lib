use crate::{
    serialize::{DynamicSized, Serialize, StaticSized},
    transaction_value::TransactionValue,
};
use secp256k1::PublicKey;
use sha3::{Digest, Sha3_256};

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
        hash.copy_from_slice(Sha3_256::digest(&self_serialized).as_slice());
        hash
    }
}

impl Serialize for TransactionOutput {
    fn from_serialized(data: &[u8], i: &mut usize) -> Result<Box<Self>, String> {
        let value = *TransactionValue::from_serialized(data, i)?;
        let pk = *PublicKey::from_serialized(data, i)?;
        Ok(Box::new(TransactionOutput { value, pk }))
    }

    fn serialize_into(&self, data: &mut [u8], i: &mut usize) -> Result<(), String> {
        self.value.serialize_into(data, i)?;
        self.pk.serialize_into(data, i)?;
        Ok(())
    }
}

impl DynamicSized for TransactionOutput {
    fn serialized_len(&self) -> usize {
        self.value.serialized_len() + PublicKey::serialized_len()
    }
}
