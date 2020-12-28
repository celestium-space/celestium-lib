use crate::{
    blockchain::Blockchain,
    merkle_forest::{MerkleForest, HASH_SIZE},
    serialize::{DynamicSized, Serialize},
    transaction::Transaction,
    transaction_input::TransactionInput,
    transaction_output::TransactionOutput,
    transaction_value::TransactionValue,
    transaction_varuint::TransactionVarUint,
    transaction_version::TransactionVersion,
    user::User,
};
use secp256k1::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, fs::File, io::Read, path::PathBuf};
pub struct Wallet {
    blockchain: Blockchain,
    pk: Option<PublicKey>,
    sk: Option<SecretKey>,
    users: HashMap<PublicKey, User>,
    blockchain_merkle_forest: MerkleForest<Transaction>,
    unspent_outputs: Vec<(Transaction, TransactionVarUint)>,
    root_lookup: HashMap<[u8; HASH_SIZE], [u8; HASH_SIZE]>,
    off_chain_merkle_forest: MerkleForest<Transaction>,
}

impl Wallet {
    pub fn new_empty(
        blockchain: Blockchain,
        pk: PublicKey,
        sk: SecretKey,
        users: HashMap<PublicKey, User>,
    ) -> Self {
        Wallet {
            blockchain,
            pk: Some(pk),
            sk: Some(sk),
            users,
            blockchain_merkle_forest: MerkleForest::new_empty(),
            unspent_outputs: Vec::new(),
            root_lookup: HashMap::new(),
            off_chain_merkle_forest: MerkleForest::new_empty(),
        }
    }

    pub fn from_binary(
        pk_bin: Vec<u8>,
        sk_bin: Vec<u8>,
        blockchain_bin: Vec<u8>,
        branches_bin: Vec<u8>,
        leafs_bin: Vec<u8>,
        unspent_outputs_bin: Vec<u8>,
        root_lookup_bin: Vec<u8>,
        off_chain_leafs_bin: Vec<u8>,
    ) -> Result<Self, String> {
        let mut users = HashMap::new();
        let pk = *PublicKey::from_serialized(&pk_bin, &mut 0, &mut users)?;
        let blockchain = *Blockchain::from_serialized(&blockchain_bin, &mut 0, &mut users)?;
        let mut merkle_forest = MerkleForest::new_empty();
        merkle_forest.add_serialized_transactions(&leafs_bin, &mut 0, &mut users)?;
        merkle_forest.add_serialized_nodes(&branches_bin)?;
        let mut i = 0;
        let mut unspent_outputs = Vec::new();
        while i < unspent_outputs_bin.len() {
            unspent_outputs.push((
                *Transaction::from_serialized(&unspent_outputs_bin, &mut i, &mut users)?,
                *TransactionVarUint::from_serialized(&unspent_outputs_bin, &mut i, &mut users)?,
            ));
        }
        let mut root_lookup: HashMap<[u8; 32], [u8; 32]> = HashMap::new();
        for chunk in root_lookup_bin.chunks(HASH_SIZE * 2) {
            let mut k = [0u8; 32];
            let mut v = [0u8; 32];
            k.copy_from_slice(&chunk[0..HASH_SIZE]);
            v.copy_from_slice(&chunk[HASH_SIZE..HASH_SIZE * 2]);
            root_lookup.insert(k, v);
        }

        let mut off_chain_merkle_forest = MerkleForest::new_empty();
        off_chain_merkle_forest.add_serialized_transactions(
            &off_chain_leafs_bin,
            &mut 0,
            &mut HashMap::new(),
        )?;
        Ok(Wallet {
            blockchain,
            pk: Some(pk),
            sk: Some(*SecretKey::from_serialized(&sk_bin, &mut 0, &mut users)?),
            users,
            blockchain_merkle_forest: merkle_forest,
            unspent_outputs,
            root_lookup,
            off_chain_merkle_forest,
        })
    }

    fn collect_for_coin_transfer(
        &self,
        value: &TransactionValue,
        pk: PublicKey,
    ) -> Result<
        (
            u128,
            Vec<TransactionInput>,
            Vec<(Transaction, TransactionVarUint)>,
        ),
        String,
    > {
        let mut dust_gathered = 0;
        let mut outputs = Vec::new();
        let mut cloned = self.unspent_outputs.clone();
        cloned.sort_by(|(a, _), (b, _)| {
            let block_a = self
                .blockchain
                .get_block_time(*self.root_lookup.get(&a.hash().unwrap()).unwrap())
                .unwrap();
            let block_b = self
                .blockchain
                .get_block_time(*self.root_lookup.get(&b.hash().unwrap()).unwrap())
                .unwrap();
            block_a.partial_cmp(&block_b).unwrap()
        });

        for (transaction, index) in cloned {
            let transaction_output = transaction.get_output(&index);
            if transaction_output.pk == pk {
                let output_value = transaction_output.get_value_clone();
                if output_value.is_coin_transfer() {
                    dust_gathered += value.get_value()?;
                    outputs.push((transaction, index));
                    if dust_gathered >= value.get_value()? + value.get_fee()? {
                        break;
                    }
                }
            }
        }
        let mut inputs = Vec::new();
        for (transaction, index) in outputs.iter() {
            let input =
                TransactionInput::from_output(transaction.get_output(&index), index.clone());
            inputs.push(input)
        }
        Ok((dust_gathered, inputs, outputs))
    }

    pub fn send(&mut self, to_pk: PublicKey, value: TransactionValue) -> Result<Vec<u8>, String> {
        match (self.pk, self.sk) {
            (Some(pk), Some(sk)) => {
                if value.is_coin_transfer() {
                    let (dust, mut inputs, used_outputs) =
                        self.collect_for_coin_transfer(&value, pk)?;
                    let change = dust - (value.get_value()? + value.get_fee()?);
                    for input in inputs.iter_mut() {
                        input.sign(sk);
                    }
                    let mut outputs = vec![TransactionOutput::new(value, to_pk)];
                    if change > 0 {
                        outputs.push(TransactionOutput::new(
                            TransactionValue::new_coin_transfer(change, 0)?,
                            pk,
                        ));
                    }
                    let transaction =
                        Transaction::new(TransactionVersion::default(), inputs, outputs);
                    let transaction_len = transaction.serialized_len();
                    let mut serialized_transaction = vec![0u8; transaction_len];
                    transaction.serialize_into(&mut serialized_transaction, &mut 0)?;
                    self.off_chain_merkle_forest
                        .add_transactions(vec![transaction])?;
                    self.unspent_outputs.retain(|x| !used_outputs.contains(&x));
                    Ok(serialized_transaction)
                } else {
                    println!("else");
                    todo!()
                }
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
        users: &mut HashMap<PublicKey, crate::user::User>,
    ) -> Result<Vec<Transaction>, String> {
        let mut transactions = Vec::new();
        let mut i = 0;
        while i < data.len() {
            let pre_i = i;
            let mut hash = [0; 32];
            hash.copy_from_slice(Sha256::digest(&data[pre_i..i]).as_slice());
            transactions.push(*Transaction::from_serialized(&data, &mut i, users)?);
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
