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
        if value == 0 {
            return TransactionVarUint { value: vec![0u8] };
        }
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
        data: &[u8],
        i: &mut usize,
        _: &mut std::collections::HashMap<secp256k1::PublicKey, crate::user::User>,
    ) -> Result<Box<Self>, String> {
        let pre_i = *i;
        while data[*i] > 0x7 {
            *i += 1;
        }
        *i += 1;
        let mut value = vec![0u8; *i - pre_i];
        value.copy_from_slice(&data[pre_i..*i]);
        Ok(Box::new(TransactionVarUint { value }))
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
        *i += self.serialized_len();
        Ok(self.serialized_len())
    }
}

impl DynamicSized for TransactionVarUint {
    fn serialized_len(&self) -> usize {
        self.value.len()
    }
}
