use crate::serialize::{Serialize, StaticSized};

const BLOCK_VERSION_LEN: usize = 4;

pub struct BlockVersion {
    value: u32,
}

impl Serialize for BlockVersion {
    fn from_serialized(
        data: &[u8],
        i: &mut usize,
        users: &mut std::collections::HashMap<secp256k1::PublicKey, crate::user::User>,
    ) -> Result<Box<Self>, String> {
        let bytes_left = data.len() - *i;
        if bytes_left < BLOCK_VERSION_LEN {
            return Err(format!(
                "Too few bytes left for parsing block version, expected at least {} got {}",
                bytes_left, BLOCK_VERSION_LEN
            ));
        }
        let bytes = [0; BLOCK_VERSION_LEN];
        bytes.copy_from_slice(&data[*i..BLOCK_VERSION_LEN]);
        let value = u32::from_be_bytes(bytes);
        Ok(Box::new(BlockVersion { value }))
    }

    fn serialize_into(&self, buffer: &mut [u8], i: &mut usize) -> Result<usize, String> {
        todo!()
    }
}

impl StaticSized for BlockVersion {
    fn serialized_len() -> usize {
        BLOCK_VERSION_LEN
    }
}
