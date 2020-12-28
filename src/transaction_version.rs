use crate::serialize::{DynamicSized, Serialize};

#[derive(Clone)]
pub struct TransactionVersion {
    value: u8,
}

impl TransactionVersion {
    pub fn default() -> Self {
        TransactionVersion { value: 0 }
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
            Ok(Box::new(TransactionVersion { value: data[*i] }))
        }
    }

    fn serialize_into(&self, data: &mut [u8], i: &mut usize) -> Result<usize, String> {
        data[*i] = self.value;
        *i += 1;
        Ok(1)
    }
}

impl DynamicSized for TransactionVersion {
    fn serialized_len(&self) -> usize {
        1
    }
}
