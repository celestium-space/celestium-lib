use crate::{
    block::BlockHash,
    blockchain::Blockchain,
    serialize::Serialize,
    transaction::{Transaction, TransactionBlock, TransactionValue},
    universal_id::UniversalId,
    user::User,
};
use secp256k1::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, fs::File, io::Read, path::PathBuf};

pub struct Wallet {
    pub blockchain: Blockchain,
    pub pk: Option<PublicKey>,
    pub sk: Option<SecretKey>,
    pub current_uid: UniversalId,
    pub transaction_blocks: Vec<TransactionBlock>,
}

impl Wallet {
    pub fn from_binary(
        blockchain_bin: Vec<u8>,
        pk_bin: Vec<u8>,
        sk_bin: Vec<u8>,
    ) -> Result<Wallet, String> {
        let mut j = 0;
        let mut k = 0;
        let mut users = HashMap::new();
        let pk = *PublicKey::from_serialized(&pk_bin, &mut j, &mut users)?;
        let uid: UniversalId;
        match users.get(&pk) {
            Some(me) => {
                uid = me.get_uid();
            }
            None => {
                let user = User::new(pk);
                uid = user.get_uid();
                users.insert(pk, user);
            }
        }
        return Ok(Wallet {
            blockchain: *Blockchain::from_binary(&blockchain_bin)?,
            current_uid: uid,
            pk: Some(pk),
            sk: Some(*SecretKey::from_serialized(&sk_bin, &mut k, &mut users)?),
            transaction_blocks: Vec::new(),
        });
    }

    pub fn send(&mut self, to_pk: PublicKey, value: TransactionValue) -> Result<bool, String> {
        match (self.pk, self.sk) {
            (Some(pk), Some(sk)) => {
                self.current_uid.increment();
                let mut transaction_block = TransactionBlock::new(
                    vec![Transaction::new(self.current_uid, pk, to_pk, value)],
                    1,
                );
                transaction_block.sign(sk);
                self.transaction_blocks.push(transaction_block);
                Ok(true)
            }
            _ => Err(String::from(
                "Wallet must have both public key and secret key to send money",
            )),
        }
    }

    pub fn mine_all_transactions(self) -> Result<Vec<u8>, String> {
        let mut unmined_block = self
            .blockchain
            .create_unmined_block(self.transaction_blocks, self.pk.unwrap())?;
        let mut hash = BlockHash::new(0);
        while !hash.contains_enough_work() {
            hash = BlockHash::from_hash(Sha256::digest(&unmined_block).as_slice().to_vec());
        }
        let mut buffer = [0; 4];
        hash.serialize_into(&mut buffer, &mut 0)?;
        unmined_block.append(&mut buffer.to_vec());
        return Ok(unmined_block);
    }

    pub fn add_serialized_block(self, serialized_block: Vec<u8>) -> Result<bool, String> {
        self.blockchain.add_serialized_block(serialized_block)?;
        return Ok(true);
    }

    pub fn get_balance(&mut self) -> Result<u32, String> {
        match &mut self.pk {
            Some(pk) => self.blockchain.get_user_value_change(pk),
            None => Err(String::from("Personal keyset not defined")),
        }
    }

    pub fn get_users(self) -> Result<HashMap<PublicKey, User>, String> {
        return self.blockchain.get_users();
    }

    pub fn load_public_key_from_file(
        public_key_file_location: &PathBuf,
    ) -> Result<PublicKey, String> {
        let mut f = File::open(public_key_file_location).unwrap();
        let buffer = &mut Vec::new();
        f.read_to_end(buffer).unwrap();
        let mut i = 0;
        return Ok(*PublicKey::from_serialized(
            buffer,
            &mut i,
            &mut HashMap::new(),
        )?);
    }
    pub fn load_secret_key_from_file(
        secret_key_file_location: &PathBuf,
    ) -> Result<SecretKey, String> {
        let mut f = File::open(secret_key_file_location).unwrap();
        let data = &mut Vec::new();
        f.read_to_end(data).unwrap();
        let mut i = 0;
        return Ok(*SecretKey::from_serialized(
            data,
            &mut i,
            &mut HashMap::new(),
        )?);
    }
}
