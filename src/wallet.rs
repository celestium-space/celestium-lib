use crate::{blockchain::Blockchain, serialize::Serialize, user::User};
use secp256k1::{PublicKey, SecretKey};
use std::{collections::HashMap, fs::File, io::Read, path::PathBuf};

pub struct Wallet {
    pub blockchain: Blockchain,
    pub pk: Option<PublicKey>,
    pub sk: Option<SecretKey>,
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
        return Ok(Wallet {
            blockchain: *Blockchain::from_binary(&blockchain_bin, pk)?,
            pk: Some(pk),
            sk: Some(*SecretKey::from_serialized(&sk_bin, &mut k, &mut users)?),
        });
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
