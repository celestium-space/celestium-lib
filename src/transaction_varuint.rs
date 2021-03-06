use crate::serialize::{DynamicSized, Serialize};
use std::{
    cmp::Eq,
    convert::From,
    fmt::{self, Display, Formatter},
    hash::Hash,
};

#[derive(Clone, Hash, Eq, PartialEq)]
pub struct TransactionVarUint {
    pub value: Vec<u8>,
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

    pub fn increase(&mut self) {
        let mut last_index = self.value.len() - 1;
        if self.value[last_index] < 0x7f {
            self.value[last_index] += 1;
        } else {
            self.value[last_index] = u8::MAX;
            if self.increase_rec(last_index) {
                last_index += 1;
            }
            self.value[last_index] = 0;
        }
    }

    fn increase_rec(&mut self, i: usize) -> bool {
        if self.value[i] == u8::MAX {
            self.value[i] = 0x80;
            if i == 0 {
                self.value.insert(0, 0x81);
                true
            } else {
                self.increase_rec(i - 1)
            }
        } else {
            self.value[i] += 1;
            false
        }
    }
}

impl From<usize> for TransactionVarUint {
    fn from(value: usize) -> Self {
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

impl Display for TransactionVarUint {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.get_value())
    }
}

impl Serialize for TransactionVarUint {
    fn from_serialized(data: &[u8], i: &mut usize) -> Result<Box<Self>, String> {
        let pre_i = *i;
        while data[*i] > 0x7f {
            *i += 1;
            if *i >= data.len() {
                return Err(format!(
                    "VarUint {:x?} does not end before input data.",
                    data.to_vec()[pre_i..].to_vec()
                ));
            }
        }

        *i += 1;

        let mut value = vec![0u8; *i - pre_i];
        value.copy_from_slice(&data[pre_i..*i]);
        Ok(Box::new(TransactionVarUint { value }))
    }

    fn serialize_into(&self, data: &mut [u8], i: &mut usize) -> Result<(), String> {
        let bytes_left = data.len() - *i;
        let bytes_needed = self.serialized_len();
        if bytes_left < bytes_needed {
            return Err(format!(
                "Too few bytes left for serializing transaction variable uint, expected at least {} got {}", bytes_needed, bytes_left
            ));
        }
        data[*i..*i + bytes_needed].copy_from_slice(&self.value);
        *i += bytes_needed;
        Ok(())
    }
}

impl DynamicSized for TransactionVarUint {
    fn serialized_len(&self) -> usize {
        self.value.len()
    }
}
