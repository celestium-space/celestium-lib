use crate::{
    serialize::{DynamicSized, Serialize},
    transaction_output::TransactionOutput,
    transaction_varuint::TransactionVarUint,
};
use secp256k1::{Message, Secp256k1, SecretKey, Signature};
use sha2::{Digest, Sha256};

const SECP256K1_SIG_LEN: usize = 64;
const HASH_SIZE: usize = 32;

#[derive(Clone)]
pub struct TransactionInput {
    tx: [u8; HASH_SIZE],
    index: TransactionVarUint,
    signature: Option<Signature>,
}

impl TransactionInput {
    pub fn from_output(output: TransactionOutput, index: TransactionVarUint) -> Self {
        TransactionInput {
            tx: output.hash(),
            index,
            signature: None,
        }
    }

    pub fn hash(&self) -> [u8; 32] {
        let mut hash = [0u8; 32];
        let mut self_serialized = vec![0u8; self.serialized_len()];
        self.serialize_into(&mut self_serialized, &mut 0).unwrap();
        hash.copy_from_slice(Sha256::digest(&self_serialized).as_slice());
        hash
    }

    pub fn sign(&mut self, sk: SecretKey) {
        let secp = Secp256k1::new();
        let message = Message::from_slice(Sha256::digest(&self.hash()).as_slice()).unwrap();
        self.signature = Some(secp.sign(&message, &sk));
    }
}

impl PartialEq for TransactionInput {
    fn eq(&self, other: &Self) -> bool {
        self.tx == other.tx && self.index == other.index && self.signature == other.signature
    }
}

impl Serialize for TransactionInput {
    fn from_serialized(
        _data: &[u8],
        _i: &mut usize,
        _users: &mut std::collections::HashMap<secp256k1::PublicKey, crate::user::User>,
    ) -> Result<Box<Self>, String> {
        todo!()
    }

    fn serialize_into(&self, _data: &mut [u8], _i: &mut usize) -> Result<usize, String> {
        todo!()
    }
}

impl DynamicSized for TransactionInput {
    fn serialized_len(&self) -> usize {
        HASH_SIZE + self.index.serialized_len() + SECP256K1_SIG_LEN
    }
}
