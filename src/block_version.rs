use crate::{
    serialize::{Serialize, StaticSized},
    user::User,
};
use secp256k1::PublicKey;
use std::collections::HashMap;

const BLOCK_VERSION_LEN: usize = 4;

pub struct BlockVersion {
    value: [u8; BLOCK_VERSION_LEN],
}

impl BlockVersion {
    pub fn default() -> Self {
        BlockVersion {
            value: [0; BLOCK_VERSION_LEN],
        }
    }
}

impl Serialize for BlockVersion {
    fn from_serialized(
        data: &[u8],
        i: &mut usize,
        _: &mut HashMap<PublicKey, User>,
    ) -> Result<Box<Self>, String> {
        let bytes_left = data.len() - *i;
        if bytes_left < Self::serialized_len() {
            return Err(format!(
                "Too few bytes left for parsing block version, expected at least {} got {}",
                Self::serialized_len(),
                bytes_left
            ));
        }
        let mut value = [0; BLOCK_VERSION_LEN];
        value.copy_from_slice(&data[*i..*i + Self::serialized_len()]);
        *i += Self::serialized_len();
        Ok(Box::new(BlockVersion { value }))
    }

    fn serialize_into(&self, data: &mut [u8], i: &mut usize) -> Result<usize, String> {
        let bytes_left = data.len() - *i;
        if bytes_left < Self::serialized_len() {
            return Err(format!(
                "Too few bytes left to serialize block version, expected at least {} got {}",
                Self::serialized_len(),
                bytes_left
            ));
        }
        data[*i..*i + Self::serialized_len()].copy_from_slice(&self.value);
        *i += Self::serialized_len();
        Ok(Self::serialized_len())
    }
}

impl StaticSized for BlockVersion {
    fn serialized_len() -> usize {
        BLOCK_VERSION_LEN
    }
}
