use crate::{
    serialize::{Serialize, StaticSized},
    user::User,
};
use secp256k1::{PublicKey, SecretKey};
use std::collections::HashMap;

const PUBLIC_KEY_COMPRESSED_SIZE: usize = 32;
const PUBLIC_KEY_UNCOMPRESSED_SIZE: usize = 64;
const SECRET_KEY_SIZE: usize = 32;

impl Serialize for PublicKey {
    fn from_serialized(
        data: &[u8],
        i: &mut usize,
        _: &mut HashMap<PublicKey, User>,
    ) -> Result<Box<PublicKey>, String> {
        if data.len() < 33 {
            return Err(format!(
                "Too little data for public key, expected at least 33 got {}",
                data.len(),
            ));
        }
        match PublicKey::from_slice(&data[*i..*i + 33]) {
            Ok(public_key) => {
                *i += PublicKey::serialized_len();
                Ok(Box::new(public_key))
            }
            Err(e) => Err(format!(
                "Could not deserialize public key {:x?}: {}",
                &data[*i..*i + 33],
                e.to_string()
            )),
        }
    }

    fn serialize_into(&self, buffer: &mut [u8], i: &mut usize) -> Result<usize, String> {
        let self_bytes = self.serialize();
        buffer[*i..*i + self_bytes.len()].copy_from_slice(&self_bytes);
        *i += self_bytes.len();
        Ok(self_bytes.len())
    }
}

impl StaticSized for PublicKey {
    fn serialized_len() -> usize {
        PUBLIC_KEY_COMPRESSED_SIZE
    }
}

impl Serialize for SecretKey {
    fn from_serialized(
        secret_key: &[u8],
        i: &mut usize,
        _: &mut HashMap<PublicKey, User>,
    ) -> Result<Box<SecretKey>, String> {
        match SecretKey::from_slice(secret_key) {
            Ok(secret_key) => {
                *i += secret_key.len();
                Ok(Box::new(secret_key))
            }
            Err(e) => Err(format!(
                "Could not deserialize secret key {:?}: {}",
                secret_key,
                e.to_string()
            )),
        }
    }

    fn serialize_into(&self, buffer: &mut [u8], i: &mut usize) -> Result<usize, String> {
        let self_bytes = self.as_ref();
        buffer.copy_from_slice(self_bytes);
        *i += self_bytes.len();
        Ok(self_bytes.len())
    }
}

impl StaticSized for SecretKey {
    fn serialized_len() -> usize {
        SECRET_KEY_SIZE
    }
}
