use crate::user::User;
use secp256k1::PublicKey;
use std::collections::HashMap;

pub trait Serialize {
    fn from_serialized(
        data: &[u8],
        i: &mut usize,
        users: &mut HashMap<PublicKey, User>,
    ) -> Result<Box<Self>, String>;
    fn serialize_into(&self, buffer: &mut [u8], i: &mut usize) -> Result<usize, String>;
    fn serialized_len(&self) -> Result<usize, String>;
}
