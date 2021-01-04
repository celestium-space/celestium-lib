use crate::magic::Magic;
use crate::block::BlockTime;
use secp256k1::Secp256k1;
use crate::block_version::BlockVersion;
use crate::{
    block::Block,
    block_hash::BlockHash,
    blockchain::Blockchain,
    merkle_forest::{MerkleForest, HASH_SIZE},
    miner::Miner,
    serialize::{DynamicSized, Serialize, StaticSized},
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
use rand::rngs::OsRng;
use std::task::Poll;
use std::{collections::HashMap, fs::File, io::Read, path::PathBuf};

pub struct BinaryWallet {
    pub blockchain_bin: Vec<u8>,
    pub pk_bin: Vec<u8>,
    pub sk_bin: Vec<u8>,
    pub mf_branches_bin: Vec<u8>,
    pub mf_leafs_bin: Vec<u8>,
    pub unspent_outputs_bin: Vec<u8>,
    pub root_lookup_bin: Vec<u8>,
    pub off_chain_transactions_bin: Vec<u8>,
}

pub struct Wallet {
    blockchain: Blockchain,
    pk: Option<PublicKey>,
    sk: Option<SecretKey>,
    users: HashMap<PublicKey, User>,
    blockchain_merkle_forest: MerkleForest<Transaction>,
    unspent_outputs: Vec<(Transaction, TransactionVarUint)>,
    root_lookup: HashMap<[u8; HASH_SIZE], [u8; HASH_SIZE]>,
    off_chain_transactions: Vec<Transaction>,
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
            off_chain_transactions: Vec::new(),
        }
    }

    pub fn from_binary(binary_wallet: BinaryWallet) -> Result<Self, String> {
        let mut users = HashMap::new();
        let pk = *PublicKey::from_serialized(&binary_wallet.pk_bin, &mut 0, &mut users)?;
        let blockchain =
            *Blockchain::from_serialized(&binary_wallet.blockchain_bin, &mut 0, &mut users)?;
        let mut merkle_forest = MerkleForest::new_empty();
        merkle_forest.add_serialized_transactions(
            &binary_wallet.mf_leafs_bin,
            &mut 0,
            &mut users,
        )?;
        merkle_forest.add_serialized_nodes(&binary_wallet.mf_branches_bin)?;
        let mut i = 0;
        let mut unspent_outputs = Vec::new();
        while i < binary_wallet.unspent_outputs_bin.len() {
            unspent_outputs.push((
                *Transaction::from_serialized(
                    &binary_wallet.unspent_outputs_bin,
                    &mut i,
                    &mut users,
                )?,
                *TransactionVarUint::from_serialized(
                    &binary_wallet.unspent_outputs_bin,
                    &mut i,
                    &mut users,
                )?,
            ));
        }
        let mut root_lookup: HashMap<[u8; 32], [u8; 32]> = HashMap::new();
        for chunk in binary_wallet.root_lookup_bin.chunks(HASH_SIZE * 2) {
            let mut k = [0u8; 32];
            let mut v = [0u8; 32];
            k.copy_from_slice(&chunk[0..HASH_SIZE]);
            v.copy_from_slice(&chunk[HASH_SIZE..HASH_SIZE * 2]);
            root_lookup.insert(k, v);
        }

        let mut i = 0;
        let mut off_chain_transactions = Vec::new();
        while i < binary_wallet.off_chain_transactions_bin.len() {
            off_chain_transactions.push(*Transaction::from_serialized(
                &binary_wallet.off_chain_transactions_bin,
                &mut i,
                &mut users,
            )?);
        }
        Ok(Wallet {
            blockchain,
            pk: Some(pk),
            sk: Some(*SecretKey::from_serialized(
                &binary_wallet.sk_bin,
                &mut 0,
                &mut users,
            )?),
            users,
            blockchain_merkle_forest: merkle_forest,
            unspent_outputs,
            root_lookup,
            off_chain_transactions,
        })
    }

    pub fn to_binary(self) -> Result<BinaryWallet, String> {
        match (self.pk, self.sk) {
            (Some(pk), Some(sk)) => {
                let mut blockchain_bin = vec![0u8; self.blockchain.serialized_len()];
                self.blockchain
                    .serialize_into(&mut blockchain_bin, &mut 0)?;
                let mut pk_bin = vec![0u8; PublicKey::serialized_len()];
                pk.serialize_into(&mut pk_bin, &mut 0)?;
                let mut sk_bin = vec![0u8; SecretKey::serialized_len()];
                sk.serialize_into(&mut sk_bin, &mut 0)?;
                let mf_branches_bin = self.blockchain_merkle_forest.serialize_all_nodes()?;
                let mf_leafs_bin = self.blockchain_merkle_forest.serialize_all_transactions()?;
                let mut unspent_outputs_bin = Vec::new();
                for unspent_output in self.unspent_outputs {
                    let (transaction, index) = unspent_output;
                    let mut unspent_output_bin =
                        vec![0u8; transaction.serialized_len() + index.serialized_len()];
                    let mut i = 0;
                    transaction.serialize_into(&mut unspent_output_bin, &mut i)?;
                    index.serialize_into(&mut unspent_output_bin, &mut i)?;
                    unspent_outputs_bin.append(&mut unspent_output_bin);
                }
                let mut root_lookup_bin = vec![0u8; self.root_lookup.len() * HASH_SIZE * 2];
                let mut i = 0;
                for root_lookup in self.root_lookup {
                    root_lookup_bin[i..i + HASH_SIZE].copy_from_slice(&root_lookup.0);
                    i += HASH_SIZE;
                    root_lookup_bin[i..i + HASH_SIZE].copy_from_slice(&root_lookup.1);
                    i += HASH_SIZE;
                }
                let mut off_chain_transactions_bin = Vec::new();
                for transaction in self.off_chain_transactions {
                    let mut transaction_bin = vec![0u8; transaction.serialized_len()];
                    transaction.serialize_into(&mut transaction_bin, &mut 0)?;
                    off_chain_transactions_bin.append(&mut transaction_bin);
                }
                Ok(BinaryWallet {
                    blockchain_bin,
                    pk_bin,
                    sk_bin,
                    mf_branches_bin,
                    mf_leafs_bin,
                    unspent_outputs_bin,
                    root_lookup_bin,
                    off_chain_transactions_bin,
                })
            }
            _ => Err(String::from(
                "Wallet must have both public key and secret key to send money",
            )),
        }
    }

    pub fn get_balance(&self) -> u128 {
        match self.pk {
            Some(pk) => {
                let mut dust_gathered = 0;
                let mut cloned = self.unspent_outputs.clone();
                for (transaction, index) in cloned {
                    let transaction_output = transaction.get_output(&index);
                    if transaction_output.pk == pk && transaction_output.value.is_coin_transfer() {
                        dust_gathered += transaction_output.value.get_value().unwrap();
                    }
                }
                dust_gathered
            },
            None => 0,
        }
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
        println!("Cloned: {}", cloned.len());
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
            if transaction_output.pk == pk && transaction_output.value.is_coin_transfer() {
                dust_gathered += transaction_output.value.get_value()?;
                outputs.push((transaction, index));
                if dust_gathered >= value.get_value()? + value.get_fee()? {
                    break;
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

    pub fn add_off_chain_transaction(&mut self, transaction: Transaction) {
        self.off_chain_transactions.push(transaction);
    }

    pub fn send(&mut self, to_pk: PublicKey, value: TransactionValue) -> Result<Vec<u8>, String> {
        match (self.pk, self.sk) {
            (Some(pk), Some(sk)) => {
                if value.is_coin_transfer() {
                    let (dust, mut inputs, used_outputs) =
                        self.collect_for_coin_transfer(&value, pk)?;
                    println!("Dust: {}", dust);
                    println!("Unused outputs: {}", used_outputs.len());
                    let change = dust - (value.get_value()? + value.get_fee()?);
                    println!("Change {}", change);
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
                    self.off_chain_transactions.push(transaction);
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

    pub fn miner_from_off_chain_transactions(&self, data: Vec<u8>) -> Result<Miner, String> {
        match self.pk {
            Some(pk) => {
                let total_fee = 0;
                let mut transactions = Vec::new();
                for transaction in self.off_chain_transactions.iter() {
                    transaction.get_total_fee();
                    transactions.push(transaction.clone());
                }
                transactions.push(Transaction::new(
                    TransactionVersion::default(),
                    Vec::new(),
                    vec![
                        TransactionOutput::new(
                            TransactionValue::new_coin_transfer(total_fee, 0)?,
                            pk,
                        ),
                        TransactionOutput::new(TransactionValue::new_id_transfer(data)?, pk),
                    ],
                ));
                let mut merkle_forest = MerkleForest::new_empty();
                merkle_forest.add_transactions(transactions.clone())?;
                let merkle_root = *BlockHash::from_serialized(
                    &merkle_forest.create_tree_from_leafs()?,
                    &mut 0,
                    &mut HashMap::new(),
                )?;
                let back_hash = *BlockHash::from_serialized(
                    &self.blockchain.get_head_hash()?,
                    &mut 0,
                    &mut HashMap::new(),
                )?;
                Miner::new_from_hashes(merkle_root, back_hash, transactions)
            }
            None => Err(String::from("Need public key to mine")),
        }
    }

    pub fn add_transactions(&mut self, transactions: Vec<Transaction>, block_hash: [u8; 32]) -> Result<bool, String> {
        match self.pk {
            Some(pk) => {
                for transaction in transactions.iter(){
                    for (i, transaction_output) in transaction.outputs.iter().enumerate() {
                        if transaction_output.pk == pk {
                            self.unspent_outputs.push((transaction.clone(), TransactionVarUint::from_usize(i)));
                            self.root_lookup.insert(transaction.hash()?, block_hash);
                        }
                    }
                }
            },
            None => {},
        }
        self.blockchain_merkle_forest.add_transactions(transactions)
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
        //         i += PAR_WORK * N_PAR_WORKERS;
        //         if i > end_i {
        //             break;
        //         }
        //     }
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

    pub fn add_block(&mut self, block: Block) -> Result<usize, String> {
        self.blockchain.add_block(block)
    }

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

    pub fn generate_test_blockchain() -> Result<BinaryWallet, String> {
        let (sk1, pk1) = Wallet::generate_ec_keys();
        let (sk2, pk2) = Wallet::generate_ec_keys();

        let my_value = TransactionValue::new_coin_transfer(u128::MAX, 0)?;
        println!(
            "Creating initial blockchain (with a little block-zero bonus of {} dust for you 😉)",
            my_value
        );
        let mut users = HashMap::new();
        let t0 = Transaction::new(
            TransactionVersion::default(),
            Vec::new(),
            vec![
                TransactionOutput::new(my_value, pk1),
                TransactionOutput::new(
                    TransactionValue::new_id_transfer("Celestium".as_bytes().to_vec())?,
                    pk1,
                ),
            ],
        );
        let b0 = Block::new(
            BlockVersion::default(),
            *BlockHash::from_serialized(&t0.hash()?, &mut 0, &mut HashMap::new())?,
            BlockHash::default(),
            BlockTime::now(),
            Magic::new(0),
        );
        let mut b0_serialized = vec![0u8; Block::serialized_len()];
        b0.serialize_into(&mut b0_serialized, &mut 0)?;
        let mut miner = Miner::new(b0_serialized, [t0].to_vec());
        println!("Mining first block...");
        let mut wallet;
        match Wallet::mine_until_complete(&mut miner) {
            Some(b) => {
                let block_hash = b.hash();
                wallet = Wallet::new_empty(Blockchain::new([b].to_vec()), pk1, sk1, users);
                wallet.add_transactions(miner.transactions, block_hash)?;
            },
            None => return Err(String::from("Could not mine first block")),
        };
        println!("First block mined!");
        &wallet.send(pk2, TransactionValue::new_coin_transfer(500, 25)?)?;
        let mut miner = wallet.miner_from_off_chain_transactions(b"Celestium2".to_vec())?;
        println!("Mining second block...");
        match Wallet::mine_until_complete(&mut miner) {
            Some(b) => {
                wallet.add_transactions(miner.transactions, b.hash())?;
                wallet.add_block(b)?;
            }
            None => return Err(String::from("Could not mine second block")),
        };
        println!("Second block mined!");
            
        wallet.to_binary()
    }

    pub fn mine_until_complete(miner: &mut Miner) -> Option<Block> {
        loop {
            match miner.do_work() {
                Poll::Ready(result) => return result,
                Poll::Pending => {}
            }
        }
    }

    fn generate_ec_keys() -> (SecretKey, PublicKey) {
        let secp = Secp256k1::new();
        let mut rng = OsRng::new().expect("OsRng");
        secp.generate_keypair(&mut rng)
    }
}
