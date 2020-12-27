use crate::{
    blockchain::Blockchain,
    merkle_forest::MerkleForest,
    serialize::{DynamicSized, Serialize},
    transaction::Transaction,
    transaction::TransactionBlock,
    transaction_value::TransactionValue,
    user::User,
};
use secp256k1::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, fs::File, io::Read, path::PathBuf};
pub struct Wallet {
    blockchain: Blockchain,
    //current_uid: UniversalId,
    pk: Option<PublicKey>,
    sk: Option<SecretKey>,
    users: HashMap<PublicKey, User>,
    merkle_forest: MerkleForest<TransactionBlock>,
}

impl Wallet {
    pub fn new(
        blockchain: Blockchain,
        pk: PublicKey,
        sk: SecretKey,
        users: HashMap<PublicKey, User>,
        merkle_forest: MerkleForest<TransactionBlock>,
    ) -> Self {
        //let self_uid = blockchain.get_user_uid(pk).unwrap();
        Wallet {
            blockchain,
            //current_uid: self_uid,
            pk: Some(pk),
            sk: Some(sk),
            users,
            merkle_forest,
        }
    }

    pub fn from_binary(
        blockchain_bin: Vec<u8>,
        branches_bin: Vec<u8>,
        leafs_bin: Vec<u8>,
        pk_bin: Vec<u8>,
        sk_bin: Vec<u8>,
    ) -> Result<Self, String> {
        let mut users = HashMap::new();
        let pk = *PublicKey::from_serialized(&pk_bin, &mut 0, &mut users)?;
        let blockchain = *Blockchain::from_serialized(&blockchain_bin, &mut 0, &mut users)?;
        // let current_uid;
        // match blockchain.get_user_uid(pk) {
        //     Ok(u) => current_uid = u,
        //     Err(_) => current_uid = UniversalId::new(false, 0),
        // }
        let mut merkle_forest =
            MerkleForest::from_serialized_transactions(&leafs_bin, &mut 0, &mut users)?;
        merkle_forest.add_serialized_nodes(&branches_bin)?;
        Ok(Wallet {
            blockchain,
            //current_uid,
            pk: Some(pk),
            sk: Some(*SecretKey::from_serialized(&sk_bin, &mut 0, &mut users)?),
            users,
            merkle_forest,
        })
    }

    pub fn send(&mut self, to_pk: PublicKey, value: TransactionValue) -> Result<Vec<u8>, String> {
        match (self.pk, self.sk) {
            (Some(pk), Some(sk)) => {
                let mut self_user = self.get_self_user()?;
                self_user.increment_uid();
                let uid = self_user.get_uid_clone();
                let mut transaction_block =
                    TransactionBlock::new(vec![Transaction::new(uid, pk, to_pk, value)], 1);
                transaction_block.sign(sk);
                let mut buffer = vec![0u8; transaction_block.serialized_len()];
                transaction_block.serialize_into(&mut buffer, &mut 0)?;
                self.merkle_forest.add_leaf(transaction_block)?;
                Ok(buffer)
            }
            _ => Err(String::from(
                "Wallet must have both public key and secret key to send money",
            )),
        }
    }

    // pub fn clear_transaction_blocks(&mut self) {
    //     self.transaction_blocks = Vec::new();
    // }

    // pub fn count_transaction_blocks(&self) -> usize {
    //     self.transaction_blocks.len()
    // }

    // pub fn create_unmined_block_from_most_valueable_transactions(
    //     &mut self,
    //     amount: usize,
    // ) -> Result<Vec<u8>, String> {
    //     match self.pk {
    //         Some(pk) => {
    //             if self.transaction_blocks.len() < amount {
    //                 return Err(format!(
    //                     "More transaction blocks selected than available, selected {} expected <= {}",
    //                     amount,
    //                     self.transaction_blocks.len()
    //                 ));
    //             };
    //             self.transaction_blocks.sort();
    //             self.blockchain
    //                 .create_unmined_block(&self.transaction_blocks[0..amount], pk)
    //         }
    //         None => Err(
    //             "Wallet must have a public key to create unmined blocks (for finders fee)"
    //                 .to_string(),
    //         ),
    //     }
    // }

    // pub fn count_transaction_fees(&self) -> Result<usize, String> {
    //     let mut total = 0usize;
    //     for transaction_block in self.transaction_blocks.iter() {
    //         for transaciton in transaction_block.transactions.iter() {
    //             if transaciton.value.is_coin_transfer()? {
    //                 total += transaciton.value.get_fee()? as usize;
    //             }
    //         }
    //     }
    //     Ok(total)
    // }

    pub fn convert_serialized_transactions(
        data: &[u8],
        users: &mut HashMap<secp256k1::PublicKey, crate::user::User>,
    ) -> Result<Vec<TransactionBlock>, String> {
        let mut transactions = Vec::new();
        let mut i = 0;
        while i < data.len() {
            let pre_i = i;
            let mut hash = [0; 32];
            hash.copy_from_slice(Sha256::digest(&data[pre_i..i]).as_slice());
            transactions.push(*TransactionBlock::from_serialized(&data, &mut i, users)?);
        }
        Ok(transactions)
    }

    // pub fn start_mining_thread<'a>(
    //     serialized_block: &'a [u8],
    //     range: Option<(usize, usize)>,
    // ) -> ScopedJoinHandle<'a, Option<Magic>> {
    //     let (mut start, end) = match range {
    //         Some(r) => (r.0, r.1),
    //         None => (0usize, usize::MAX),
    //     };
    //     let block_len = serialized_block.len();
    //     let magic_byte_count = 1usize;
    //     let my_serialized_block = vec![0u8; block_len + magic_byte_count];
    //     my_serialized_block[..my_serialized_block.len() - 1].copy_from_slice(serialized_block);
    //     let mut magic = Magic::new(start as u64, 1);
    //     let i = start;
    //     while i < end || variable {
    //         magic
    //             .serialize_into(
    //                 &mut my_serialized_block,
    //                 &mut (block_len - magic_byte_count),
    //             )
    //             .unwrap();
    //         let hash = *BlockHash::from_serialized(
    //             Sha256::digest(&my_serialized_block).as_slice(),
    //             &mut 0,
    //             &mut HashMap::new(),
    //         )
    //         .unwrap();
    //         if hash.contains_enough_work() {
    //             return Some(magic);
    //         }
    //         magic.increase();
    //         if variable {
    //             return i;
    //         }
    //     }
    //     None
    // }

    // pub fn mine_transaction_blocks(
    //     &self,
    //     transaction_blocks: &[TransactionBlock],
    //     range: Option<(u32, u32)>,
    // ) -> Result<Vec<u8>, String> {
    //     let mut unmined_block = self
    //         .blockchain
    //         .create_unmined_block(transaction_blocks, self.pk.unwrap())?;

    //     let mut magic_with_enough_work = None;
    //     let (mut i, end_i) = match range {
    //         Some(r) => (r.0, r.1),
    //         None => (0, u32::MAX),
    //     };
    //     let mut latest_print = 0.1;
    //     let print_scale = 0.1;
    //     while magic_with_enough_work.is_none() {
    //         let list: Vec<u32> = (0..N_PAR_WORKERS).collect();
    //         let slice = list.as_slice();
    //         let magic = slice.par_iter().filter_map(|&j| {
    //             let mut my_unmined_block = vec![0; unmined_block.len()];
    //             my_unmined_block.copy_from_slice(&unmined_block);
    //             let total_len = my_unmined_block.len();
    //             let mut magic = Magic::new(i + j * PAR_WORK);
    //             for _ in 0..PAR_WORK {
    //                 let magic_len = magic.serialized_len().unwrap();
    //                 magic
    //                     .serialize_into(&mut my_unmined_block, &mut (total_len - magic_len))
    //                     .unwrap();
    //                 let hash = *BlockHash::from_serialized(
    //                     Sha256::digest(&my_unmined_block).as_slice(),
    //                     &mut 0,
    //                     &mut HashMap::new(),
    //                 )
    //                 .unwrap();
    //                 if hash.contains_enough_work() {
    //                     return Some(magic);
    //                 }
    //                 magic.increase();
    //             }
    //             None
    //         });
    //         let best_magic = magic.min();
    //         if best_magic.is_some() {
    //             magic_with_enough_work = best_magic;
    //         } else if ((i as f64 / end_i as f64) * 100f64) > latest_print + print_scale {
    //             latest_print += print_scale;
    //             println!("{0:.1}% mined", latest_print);
    //         }
    //         i += PAR_WORK * N_PAR_WORKERS;
    //         if i > end_i {
    //             break;
    //         }
    //     }
    //     let magic = magic_with_enough_work.unwrap();
    //     let mut i = unmined_block.len() - magic.serialized_len()?;
    //     magic.serialize_into(&mut unmined_block, &mut i)?;
    //     Ok(unmined_block)
    // }

    // pub fn mine_most_valueable_transaction_blocks(
    //     &mut self,
    //     amount: usize,
    // ) -> Result<Vec<u8>, String> {
    //     if self.transaction_blocks.len() < amount {
    //         return Err(format!(
    //             "More transaction blocks selected than available, selected {} expected <= {}",
    //             amount,
    //             self.transaction_blocks.len()
    //         ));
    //     };
    //     self.transaction_blocks.sort();
    //     self.mine_transaction_blocks(&self.transaction_blocks[0..amount], None)
    // }

    // pub fn add_serialized_transaction_block(
    //     mut self,
    //     serialized_transaction_block: Vec<u8>,
    // ) -> Result<Vec<u8>, String> {
    //     let transaction_block = *TransactionBlock::from_serialized(
    //         &serialized_transaction_block,
    //         &mut 0,
    //         &mut HashMap::new(),
    //     )?;
    //     self.transaction_blocks.push(transaction_block);
    //     self.get_serialized_transaction_blocks()
    // }

    // pub fn get_serialized_transaction_blocks(self) -> Result<Vec<u8>, String> {
    //     let mut len = 0;
    //     for transaction_block in self.transaction_blocks.iter() {
    //         len += transaction_block.serialized_len()?;
    //     }
    //     let mut buffer = vec![0u8; len];
    //     for transaction_block in self.transaction_blocks {
    //         transaction_block.serialize_into(&mut buffer, &mut 0)?;
    //     }
    //     Ok(buffer)
    // }

    pub fn add_serialized_block(&mut self, serialized_block: Vec<u8>) -> Result<Vec<u8>, String> {
        self.blockchain
            .add_serialized_block(serialized_block, &mut self.users)
    }

    pub fn get_serialized_blockchain(&self) -> Result<Vec<u8>, String> {
        let mut buffer = vec![0; self.blockchain.serialized_len()];
        self.blockchain.serialize_into(&mut buffer, &mut 0)?;
        Ok(buffer)
    }

    pub fn get_self_user(&self) -> Result<User, String> {
        match self.pk {
            Some(pk) => match self.users.get(&pk) {
                Some(me) => Ok(me.clone()),
                None => Err(String::from("Personal keyset not among users")),
            },
            None => Err(String::from("Personal keyset not defined")),
        }
    }

    pub fn load_public_key_from_file(
        public_key_file_location: &PathBuf,
    ) -> Result<PublicKey, String> {
        let mut f = File::open(public_key_file_location).unwrap();
        let buffer = &mut Vec::new();
        f.read_to_end(buffer).unwrap();
        let mut i = 0;
        Ok(*PublicKey::from_serialized(
            buffer,
            &mut i,
            &mut HashMap::new(),
        )?)
    }
    pub fn load_secret_key_from_file(
        secret_key_file_location: &PathBuf,
    ) -> Result<SecretKey, String> {
        let mut f = File::open(secret_key_file_location).unwrap();
        let data = &mut Vec::new();
        f.read_to_end(data).unwrap();
        let mut i = 0;
        Ok(*SecretKey::from_serialized(
            data,
            &mut i,
            &mut HashMap::new(),
        )?)
    }
}
