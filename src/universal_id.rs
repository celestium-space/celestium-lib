use crate::{serialize::Serialize, user::User};
use secp256k1::PublicKey;
use std::{collections::HashMap, fmt};

#[derive(Copy, Clone)]
pub struct UniversalId {
    is_continuation: bool,
    value: u16,
}

impl UniversalId {
    pub fn new(is_continuation: bool, value: u16) -> UniversalId {
        UniversalId {
            is_continuation,
            value,
        }
    }

    pub fn is_continuation(&self) -> bool {
        self.is_continuation
    }

    pub fn get_value(&self) -> u16 {
        self.value
    }

    pub fn increment(&mut self) {
        self.value += 1
    }
}

impl fmt::Display for UniversalId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "BID:{}", self.value)
    }
}

impl Serialize for UniversalId {
    fn from_serialized(
        data: &[u8],
        i: &mut usize,
        _: &mut HashMap<PublicKey, User>,
    ) -> Result<Box<UniversalId>, String> {
        let uid = UniversalId {
            is_continuation: data[*i] & 0x80 > 0,
            value: (((data[*i] & 0x3f) as u16) << 8) + data[*i + 1] as u16,
        };
        *i += 2;
        Ok(Box::new(uid))
    }
    fn serialize_into(&self, buffer: &mut [u8], i: &mut usize) -> Result<usize, String> {
        let mut first_byte = (self.value >> 8) as u8;
        if self.is_continuation {
            first_byte ^= 0x80;
        }
        buffer[*i] = first_byte;
        buffer[*i + 1] = (self.value & 0xff) as u8;
        *i += 2;
        Ok(2)
    }

    fn serialized_len(&self) -> Result<usize, String> {
        Ok(2)
    }
}
