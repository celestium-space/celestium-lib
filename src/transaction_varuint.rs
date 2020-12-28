use crate::serialize::{DynamicSized, Serialize};

#[derive(Clone)]
pub struct TransactionVarUint {
    value: Vec<u8>,
}

impl TransactionVarUint {
    pub fn get_value(&self) -> usize {
        let mut value = 0usize;
        for byte in self.value.iter() {
            value <<= 7;
            value += (byte & 0x7f) as usize;
        }
        value
    }

    pub fn from_usize(value: usize) -> Self {
        let mut tmp_value = value;
        let mut bytes = Vec::new();
        while tmp_value > 0 {
            bytes.insert(0, 0x80 + (tmp_value & 0x7f) as u8);
            tmp_value >>= 7;
        }
        if let Some(last) = bytes.last_mut() {
            *last &= 0x7fu8;
        }
        TransactionVarUint { value: bytes }
    }
}

impl PartialEq for TransactionVarUint {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl Serialize for TransactionVarUint {
    fn from_serialized(
        _data: &[u8],
        _i: &mut usize,
        _users: &mut std::collections::HashMap<secp256k1::PublicKey, crate::user::User>,
    ) -> Result<Box<Self>, String> {
        println!("TransactionVarUint from_serialized");
        todo!()
    }

    fn serialize_into(&self, data: &mut [u8], i: &mut usize) -> Result<usize, String> {
        let bytes_left = data.len() - *i;
        if bytes_left < self.serialized_len() {
            return Err(format!(
                "Too few bytes left for serializing transaction variable uint, expected at least {} got {}",
                self.serialized_len(),
                bytes_left
            ));
        }
        data[*i..*i + self.serialized_len()].copy_from_slice(&self.value);
        Ok(self.serialized_len())
    }
}

impl DynamicSized for TransactionVarUint {
    fn serialized_len(&self) -> usize {
        self.value.len()
    }
}
