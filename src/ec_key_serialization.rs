use crate::serialize::{Serialize, StaticSized};
use secp256k1::{PublicKey, SecretKey};

pub const PUBLIC_KEY_COMPRESSED_SIZE: usize = 33;
//const PUBLIC_KEY_UNCOMPRESSED_SIZE: usize = 64;
const SECRET_KEY_SIZE: usize = 32;

impl Serialize for PublicKey {
    fn from_serialized(data: &[u8], i: &mut usize) -> Result<Box<PublicKey>, String> {
        let bytes_left = data.len() - *i;
        if bytes_left < PUBLIC_KEY_COMPRESSED_SIZE {
            return Err(format!(
                "Too little data for public key, expected at least {} got {}",
                PUBLIC_KEY_COMPRESSED_SIZE,
                data.len(),
            ));
        }
        match PublicKey::from_slice(&data[*i..*i + PUBLIC_KEY_COMPRESSED_SIZE]) {
            Ok(public_key) => {
                *i += PublicKey::serialized_len();
                Ok(Box::new(public_key))
            }
            Err(e) => Err(format!(
                "Could not deserialize public key {:x?} at {} - {}",
                &data[*i..*i + PUBLIC_KEY_COMPRESSED_SIZE],
                *i,
                e.to_string()
            )),
        }
    }

    fn serialize_into(&self, data: &mut [u8], i: &mut usize) -> Result<(), String> {
        let bytes_left = data.len() - *i;
        if bytes_left < Self::serialized_len() {
            return Err(format!(
                "Too few bytes left to serialize public key into, expected at least {} got {}",
                Self::serialized_len(),
                bytes_left
            ));
        }
        let self_bytes = self.serialize();
        data[*i..*i + self_bytes.len()].copy_from_slice(&self_bytes);
        *i += self_bytes.len();
        Ok(())
    }
}

impl StaticSized for PublicKey {
    fn serialized_len() -> usize {
        PUBLIC_KEY_COMPRESSED_SIZE
    }
}

impl Serialize for SecretKey {
    fn from_serialized(secret_key: &[u8], i: &mut usize) -> Result<Box<SecretKey>, String> {
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

    fn serialize_into(&self, data: &mut [u8], i: &mut usize) -> Result<(), String> {
        let self_bytes = self.as_ref();
        let bytes_left = data.len() - *i;
        if bytes_left < self_bytes.len() {
            return Err(format!(
                "Too few bytes left to serialize secret key into, expected at least {} got {}",
                Self::serialized_len(),
                bytes_left
            ));
        }
        data.copy_from_slice(self_bytes);
        *i += self_bytes.len();
        Ok(())
    }
}

impl StaticSized for SecretKey {
    fn serialized_len() -> usize {
        SECRET_KEY_SIZE
    }
}
