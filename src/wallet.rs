use crate::{
    block::Block,
    block_hash::BlockHash,
    block_version::BlockVersion,
    blockchain::Blockchain,
    ec_key_serialization::PUBLIC_KEY_COMPRESSED_SIZE,
    merkle_forest::{MerkleForest, Node, HASH_SIZE},
    miner::Miner,
    serialize::{DynamicSized, Serialize, StaticSized},
    transaction::{self, Transaction},
    transaction_input::TransactionInput,
    transaction_output::TransactionOutput,
    transaction_value::TransactionValue,
    transaction_varuint::TransactionVarUint,
};
use indicatif::{ProgressBar, ProgressIterator};
use rand::rngs::ThreadRng;
use rayon::{prelude::*, ThreadPool, ThreadPoolBuilder};
use secp256k1::Secp256k1;
use secp256k1::{PublicKey, SecretKey};
use sha3::{Digest, Sha3_256};
use std::{
    collections::{hash_map::RandomState, HashMap, HashSet},
    io::Write,
    time::Instant,
};
use std::{io, task::Poll};

pub const DEFAULT_N_THREADS: u64 = 0x16;
pub const DEFAULT_PAR_WORK: u64 = 0x200000;

pub struct BinaryWallet {
    pub blockchain_bin: Vec<u8>,
    pub pk_bin: Vec<u8>,
    pub sk_bin: Vec<u8>,
    pub mf_branches_bin: Vec<u8>,
    pub mf_leafs_bin: Vec<u8>,
    pub unspent_outputs_bin: Vec<u8>,
    pub nft_lookups_bin: Vec<u8>,
    pub root_lookup_bin: Vec<u8>,
    pub off_chain_transactions_bin: Vec<u8>,
}

pub struct Wallet {
    blockchain: Blockchain,
    pk: Option<PublicKey>,
    sk: Option<SecretKey>,
    blockchain_merkle_forest: MerkleForest<Transaction>,
    pub unspent_outputs: HashMap<
        PublicKey,
        HashMap<([u8; HASH_SIZE], [u8; HASH_SIZE], TransactionVarUint), TransactionOutput>,
    >,
    nft_lookups: HashMap<[u8; HASH_SIZE], ([u8; HASH_SIZE], [u8; HASH_SIZE], TransactionVarUint)>,
    root_lookup: HashMap<[u8; HASH_SIZE], [u8; HASH_SIZE]>,
    pub off_chain_transactions: HashMap<[u8; HASH_SIZE], Transaction>,
    thread_pool: ThreadPool,
    is_block_miner: bool,
}

impl Wallet {
    pub fn new_with_treadpool(
        pk: PublicKey,
        sk: SecretKey,
        is_block_miner: bool,
        thread_pool: ThreadPool,
    ) -> Result<Self, String> {
        Ok(Wallet {
            blockchain: Blockchain::new(Vec::new()),
            pk: Some(pk),
            sk: Some(sk),
            blockchain_merkle_forest: MerkleForest::new_empty(),
            unspent_outputs: HashMap::new(),
            nft_lookups: HashMap::new(),
            root_lookup: HashMap::new(),
            off_chain_transactions: HashMap::new(),
            thread_pool,
            is_block_miner,
        })
    }

    pub fn new(pk: PublicKey, sk: SecretKey, is_block_miner: bool) -> Result<Self, String> {
        Wallet::new_with_treadpool(
            pk,
            sk,
            is_block_miner,
            ThreadPoolBuilder::new()
                .num_threads(DEFAULT_N_THREADS as usize)
                .build()
                .unwrap(),
        )
    }

    pub fn from_binary(
        binary_wallet: &BinaryWallet,
        is_block_miner: bool,
        reload_unspent_outputs: bool,
        ignore_off_chain_transactions: bool,
    ) -> Result<Self, String> {
        let pk = *PublicKey::from_serialized(&binary_wallet.pk_bin, &mut 0)?;
        let blockchain = *Blockchain::from_serialized(&binary_wallet.blockchain_bin, &mut 0)?;
        let mut merkle_forest = MerkleForest::new_empty();
        merkle_forest.add_serialized_transactions(&binary_wallet.mf_leafs_bin, &mut 0)?;
        merkle_forest.add_serialized_nodes(&binary_wallet.mf_branches_bin)?;
        let mut unspent_outputs: HashMap<
            PublicKey,
            HashMap<([u8; HASH_SIZE], [u8; HASH_SIZE], TransactionVarUint), TransactionOutput>,
        > = HashMap::new();

        let mut i = 0;
        let mut off_chain_transactions = HashMap::new();
        if !ignore_off_chain_transactions {
            while i < binary_wallet.off_chain_transactions_bin.len() {
                let transaction = *Transaction::from_serialized(
                    &binary_wallet.off_chain_transactions_bin,
                    &mut i,
                )?;
                off_chain_transactions.insert(transaction.hash(), transaction);
            }
        }

        if !reload_unspent_outputs {
            let mut i = 0;
            while i < binary_wallet.unspent_outputs_bin.len() {
                let pk: PublicKey =
                    *PublicKey::from_serialized(&binary_wallet.unspent_outputs_bin, &mut i)?;
                let output_count = TransactionVarUint::from_serialized(
                    &binary_wallet.unspent_outputs_bin,
                    &mut i,
                )?
                .get_value();

                let mut pk_unspent_outputs = HashMap::new();

                let pb = if output_count > 100_000 {
                    Some(ProgressBar::with_message(
                        ProgressBar::new(output_count as u64),
                        format!(
                            "Loading big PK [0x{}...] (probably block zero)",
                            hex::encode(&pk.serialize()[..8])
                        ),
                    ))
                } else {
                    None
                };
                for _ in 0..output_count {
                    let mut block_hash: [u8; HASH_SIZE] = [0u8; HASH_SIZE];
                    block_hash
                        .copy_from_slice(&binary_wallet.unspent_outputs_bin[i..i + HASH_SIZE]);
                    i += HASH_SIZE;
                    let mut transaction_hash: [u8; HASH_SIZE] = [0u8; HASH_SIZE];
                    transaction_hash
                        .copy_from_slice(&binary_wallet.unspent_outputs_bin[i..i + HASH_SIZE]);
                    i += HASH_SIZE;

                    let key = (
                        block_hash,
                        transaction_hash,
                        *TransactionVarUint::from_serialized(
                            &binary_wallet.unspent_outputs_bin,
                            &mut i,
                        )?,
                    );
                    let value = *TransactionOutput::from_serialized(
                        &binary_wallet.unspent_outputs_bin,
                        &mut i,
                    )?;

                    pk_unspent_outputs.insert(key, value);

                    if let Some(ref pb) = pb {
                        pb.inc(1);
                    }
                }
                if let Some(ref pb) = pb {
                    pb.finish();
                }
                unspent_outputs.insert(pk, pk_unspent_outputs);
            }
        } else {
            let mut tmp_unspent_outputs: HashMap<
                ([u8; HASH_SIZE], [u8; HASH_SIZE], TransactionVarUint),
                TransactionOutput,
                RandomState,
            > = HashMap::new();

            for (block_hash, _) in blockchain.blocks.iter() {
                for (nodes, transactions) in merkle_forest.get_merkle_tree(*block_hash) {
                    println!("{} | {}", nodes.len(), transactions.len());
                    for transaction in transactions.clone() {
                        let outputs = transaction.get_outputs();
                        println!("{}", outputs.len());
                        let pb = if outputs.len() > 100_000 {
                            Some(ProgressBar::with_message(
                                ProgressBar::new(outputs.len() as u64),
                                format!(
                                    "Loading big PK [0x{}...] (probably block zero)",
                                    hex::encode(&pk.serialize()[..8])
                                ),
                            ))
                        } else {
                            None
                        };
                        for (i, output) in outputs.iter().enumerate() {
                            tmp_unspent_outputs.insert(
                                (*block_hash, transaction.hash(), TransactionVarUint::from(i)),
                                output.clone(),
                            );
                            if let Some(ref pb) = pb {
                                pb.inc(1);
                            }
                        }
                        if let Some(ref pb) = pb {
                            pb.finish();
                        }
                    }

                    // Cannot happen in same loop as one block can both create and spent the same output
                    for transaction in transactions {
                        if !transaction.is_base_transaction() {
                            for input in transaction.get_inputs() {
                                if let None = tmp_unspent_outputs.remove(&(
                                    input.block_hash,
                                    input.transaction_hash,
                                    input.index,
                                )) {
                                    panic!("ERROR");
                                }
                            }
                        }
                    }
                }
            }
            if !ignore_off_chain_transactions {
                for transaction in off_chain_transactions.values() {
                    for output in transaction.get_outputs() {
                        tmp_unspent_outputs.insert(
                            (
                                [0u8; HASH_SIZE],
                                transaction.hash(),
                                TransactionVarUint::from(i),
                            ),
                            output,
                        );
                    }
                }

                // Cannot happen in same loop as one block can both create and spent the same output
                for transaction in off_chain_transactions.values() {
                    if !transaction.is_base_transaction() {
                        for input in transaction.get_inputs() {
                            if let None = tmp_unspent_outputs.remove(&(
                                input.block_hash,
                                input.transaction_hash,
                                input.index,
                            )) {
                                panic!("ERROR");
                            }
                        }
                    }
                }
            }
        }

        let mut i = 0;
        let mut nft_lookup = HashMap::new();
        while i < binary_wallet.nft_lookups_bin.len() {
            let mut nft_hash: [u8; HASH_SIZE] = [0u8; HASH_SIZE];
            nft_hash.copy_from_slice(&binary_wallet.nft_lookups_bin[i..i + HASH_SIZE]);
            i += HASH_SIZE;
            let mut block_hash: [u8; HASH_SIZE] = [0u8; HASH_SIZE];
            block_hash.copy_from_slice(&binary_wallet.nft_lookups_bin[i..i + HASH_SIZE]);
            i += HASH_SIZE;
            let mut transaction_hash: [u8; HASH_SIZE] = [0u8; HASH_SIZE];
            transaction_hash.copy_from_slice(&binary_wallet.nft_lookups_bin[i..i + HASH_SIZE]);
            i += HASH_SIZE;
            nft_lookup.insert(
                nft_hash,
                (
                    block_hash,
                    transaction_hash,
                    *TransactionVarUint::from_serialized(&binary_wallet.nft_lookups_bin, &mut i)?,
                ),
            );
        }

        let mut root_lookup: HashMap<[u8; 32], [u8; 32]> = HashMap::new();
        for chunk in binary_wallet.root_lookup_bin.chunks(HASH_SIZE * 2) {
            let mut k = [0u8; 32];
            let mut v = [0u8; 32];
            k.copy_from_slice(&chunk[0..HASH_SIZE]);
            v.copy_from_slice(&chunk[HASH_SIZE..HASH_SIZE * 2]);
            root_lookup.insert(k, v);
        }

        let thread_pool = ThreadPoolBuilder::new()
            .num_threads(DEFAULT_N_THREADS as usize)
            .build()
            .unwrap();
        Ok(Wallet {
            blockchain,
            pk: Some(pk),
            sk: Some(*SecretKey::from_serialized(&binary_wallet.sk_bin, &mut 0)?),
            blockchain_merkle_forest: merkle_forest,
            unspent_outputs,
            nft_lookups: nft_lookup,
            root_lookup,
            off_chain_transactions,
            thread_pool,
            is_block_miner,
        })
    }

    pub fn to_binary(&self) -> Result<BinaryWallet, String> {
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
                for (pk, pk_unspent_outputs) in self.unspent_outputs.iter() {
                    // Create header (public key + unspent output count)
                    let mut i = 0;
                    let body_count = TransactionVarUint::from(pk_unspent_outputs.len());
                    let mut header =
                        vec![0u8; body_count.serialized_len() + PUBLIC_KEY_COMPRESSED_SIZE];
                    pk.serialize_into(&mut header, &mut i)?;
                    body_count.serialize_into(&mut header, &mut i)?;
                    unspent_outputs_bin.append(&mut header);

                    // Append body (all unspent outputs for the public key)
                    for ((block_hash, transaction_hash, index), output) in pk_unspent_outputs {
                        let mut unspent_output_bin = vec![
                            0u8;
                            block_hash.len()
                                + transaction_hash.len()
                                + index.serialized_len()
                                + output.serialized_len()
                        ];
                        let mut i = 0;
                        unspent_output_bin[i..i + HASH_SIZE].copy_from_slice(block_hash);
                        i += HASH_SIZE;
                        unspent_output_bin[i..i + HASH_SIZE].copy_from_slice(transaction_hash);
                        i += HASH_SIZE;
                        index.serialize_into(&mut unspent_output_bin, &mut i)?;
                        output.serialize_into(&mut unspent_output_bin, &mut i)?;
                        unspent_outputs_bin.append(&mut unspent_output_bin);
                    }
                }

                let mut nft_lookups_bin = Vec::new();
                for nft_lookup in self.nft_lookups.iter() {
                    let (nft_hash, (block_hash, transaction_hash, index)) = nft_lookup;
                    let mut nft_lookup_bin = vec![
                        0u8;
                        nft_hash.len()
                            + block_hash.len()
                            + transaction_hash.len()
                            + index.serialized_len()
                    ];
                    let mut i = 0;
                    nft_lookup_bin[i..i + HASH_SIZE].copy_from_slice(nft_hash);
                    i += HASH_SIZE;
                    nft_lookup_bin[i..i + HASH_SIZE].copy_from_slice(block_hash);
                    i += HASH_SIZE;
                    nft_lookup_bin[i..i + HASH_SIZE].copy_from_slice(transaction_hash);
                    i += HASH_SIZE;
                    index.serialize_into(&mut nft_lookup_bin, &mut i)?;
                    nft_lookups_bin.append(&mut nft_lookup_bin);
                }
                let mut root_lookup_bin = vec![0u8; self.root_lookup.len() * HASH_SIZE * 2];
                let mut i = 0;
                for root_lookup in self.root_lookup.iter() {
                    root_lookup_bin[i..i + HASH_SIZE].copy_from_slice(root_lookup.0);
                    i += HASH_SIZE;
                    root_lookup_bin[i..i + HASH_SIZE].copy_from_slice(root_lookup.1);
                    i += HASH_SIZE;
                }
                let mut off_chain_transactions_bin = Vec::new();
                for transaction in self.off_chain_transactions.values() {
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
                    nft_lookups_bin,
                    root_lookup_bin,
                    off_chain_transactions_bin,
                })
            }
            _ => Err(String::from(
                "Wallet must have both public key and secret key to send money",
            )),
        }
    }

    pub fn count_blocks(&self) -> usize {
        self.blockchain.len()
    }

    pub fn get_mining_value(&self) -> Result<u128, String> {
        let mut value = 0;
        for transaction in self.off_chain_transactions.values() {
            value += transaction.get_total_fee();
        }
        Ok(value)
    }

    pub fn verify_transaction(&self, transaction: Transaction) -> Result<(), String> {
        transaction.verify_signatures(&self.blockchain_merkle_forest)
    }

    pub fn get_balance(&self, pk: PublicKey) -> Result<u128, String> {
        let mut dust_gathered = 0;
        for ((_, _, _), transaction_output) in
            self.unspent_outputs.get(&pk).unwrap_or(&HashMap::new())
        {
            if transaction_output.pk == pk && transaction_output.value.is_coin_transfer() {
                dust_gathered += transaction_output.value.get_value().unwrap();
            }
        }
        for transaction in self.off_chain_transactions.values() {
            for transaction_output in transaction.get_outputs() {
                if transaction_output.pk == pk && transaction_output.value.is_coin_transfer() {
                    dust_gathered += transaction_output.value.get_value().unwrap();
                }
            }
        }
        Ok(dust_gathered)
    }

    #[allow(clippy::type_complexity)]
    pub fn collect_for_coin_transfer(
        &self,
        value: &TransactionValue,
        pk: PublicKey,
        black_list: HashSet<([u8; HASH_SIZE], usize)>,
    ) -> Result<(u128, Vec<TransactionInput>), String> {
        let mut dust_gathered = 0;
        let mut inputs = Vec::new();
        for ((block_hash, transaction_hash, index), transaction_output) in
            self.unspent_outputs.get(&pk).unwrap_or(&HashMap::new())
        {
            if black_list.contains(&(*transaction_hash, index.get_value())) {
                continue;
            }
            if transaction_output.pk == pk
                && transaction_output.value.is_coin_transfer()
                && transaction_output.value.get_value()? > 0
            {
                let input = TransactionInput::new(*block_hash, *transaction_hash, index.clone());
                inputs.push(input);
                dust_gathered += transaction_output.value.get_value()?;
                if dust_gathered >= value.get_value()? + value.get_fee()? {
                    break;
                }
            }
        }
        Ok((dust_gathered, inputs))
    }

    pub fn add_off_chain_transaction(
        &mut self,
        transaction: Transaction,
        pks: Vec<PublicKey>,
    ) -> Result<(), String> {
        transaction.verify_signatures(&self.blockchain_merkle_forest)?;
        if !transaction.contains_enough_work()? {
            return Err("Transaction does not contain enough work".to_string());
        }

        if transaction.is_base_transaction() {
            let base_transaction_input_block_hash = transaction.get_inputs()[0].block_hash;
            let current_blockchain_head_hash = self.get_head_hash();
            if base_transaction_input_block_hash != current_blockchain_head_hash {
                return Err(format!(
                    "Base transaction input block hash {:x?} does not match head block hash {:x?}",
                    base_transaction_input_block_hash, current_blockchain_head_hash
                ));
            }
        } else {
            let mut actual_inputs = vec![];
            for pk in pks {
                for input in transaction.get_inputs() {
                    let output_ref = (
                        input.block_hash,
                        input.transaction_hash,
                        input.index.clone(),
                    );
                    if !self
                        .unspent_outputs
                        .get(&pk)
                        .unwrap_or(&HashMap::new())
                        .contains_key(&output_ref)
                    {
                        return Err(format!(
                            "({:x?}, {:x?}, {}), does not refer to an unspent output",
                            input.transaction_hash,
                            input.block_hash,
                            input.index.clone().get_value(),
                        ));
                    } else {
                        actual_inputs.push((pk, output_ref.clone()));
                    }
                }
            }

            for (index, output) in transaction.get_outputs().iter().enumerate() {
                let pk = output.pk;
                if !self.unspent_outputs.contains_key(&pk) {
                    self.unspent_outputs.insert(pk, HashMap::new());
                }
                self.unspent_outputs.get_mut(&pk).unwrap().insert(
                    (
                        transaction.hash(),
                        [0u8; HASH_SIZE],
                        TransactionVarUint::from(index),
                    ),
                    output.clone(),
                );
            }

            for (pk, output_ref) in actual_inputs {
                self.unspent_outputs
                    .get_mut(&pk)
                    .unwrap()
                    .remove(&output_ref);
                if self.unspent_outputs[&pk].len() == 0 {
                    self.unspent_outputs.remove(&pk);
                }
            }
        }

        self.off_chain_transactions
            .insert(transaction.hash(), transaction);
        Ok(())
    }

    pub fn send_with_sk(
        &mut self,
        to_pk: PublicKey,
        value: TransactionValue,
        from_pk: PublicKey,
        from_sk: SecretKey,
    ) -> Result<Vec<u8>, String> {
        if value.is_coin_transfer() {
            let (dust, inputs) = self.collect_for_coin_transfer(&value, from_pk, HashSet::new())?;
            let change = dust - (value.get_value()? + value.get_fee()?);
            let mut outputs = vec![TransactionOutput::new(value, to_pk)];
            if change > 0 {
                outputs.push(TransactionOutput::new(
                    TransactionValue::new_coin_transfer(change, 0)?,
                    from_pk,
                ));
            }
            let mut transaction = Transaction::new(inputs, outputs)?;
            for i in 0..transaction.count_inputs() {
                transaction.sign(from_sk, i)?;
            }
            let transaction_len = transaction.serialized_len();
            let mut serialized_transaction = vec![0u8; transaction_len];
            transaction.serialize_into(&mut serialized_transaction, &mut 0)?;
            self.add_off_chain_transaction(transaction, vec![from_pk])?;
            Ok(serialized_transaction)
        } else {
            Err(String::from("Send ID not implented"))
        }
    }

    pub fn send(&mut self, to_pk: PublicKey, value: TransactionValue) -> Result<Vec<u8>, String> {
        match (self.pk, self.sk) {
            (Some(pk), Some(sk)) => self.send_with_sk(to_pk, value, pk, sk),
            _ => Err(String::from(
                "Wallet must have both public key and secret key to send money",
            )),
        }
    }

    pub fn mining_data_from_off_chain_transactions(
        &self,
    ) -> Result<(Block, Vec<Transaction>), String> {
        match self.pk {
            Some(pk) => {
                let mut total_fee = 0;
                let mut transactions = Vec::new();
                for transaction in self.off_chain_transactions.values() {
                    total_fee += transaction.get_total_fee();
                    transactions.push(transaction.clone());
                }
                transactions.push(self.mine_transaction(
                    DEFAULT_N_THREADS,
                    DEFAULT_PAR_WORK,
                    Transaction::new_coin_base_transaction(
                        self.get_head_hash(),
                        [0u8; transaction::BASE_TRANSACTION_MESSAGE_LEN],
                        TransactionOutput::new(
                            TransactionValue::new_coin_transfer(total_fee, 0)?,
                            pk,
                        ),
                    ),
                )?);
                let (_, merkle_root) = MerkleForest::new_complete_from_leafs(transactions.clone())?;
                let back_hash =
                    *BlockHash::from_serialized(&self.blockchain.get_head_hash(), &mut 0)?;
                let magic = TransactionVarUint::from(0);
                let version = BlockVersion::default();
                let block = Block::new(version, BlockHash::from(merkle_root), back_hash, magic);
                Ok((block, transactions))
            }
            None => Err(String::from("Need public key to mine")),
        }
    }

    pub fn get_head_hash(&self) -> [u8; 32] {
        self.blockchain.get_head_hash()
    }

    pub fn add_on_chain_transactions(
        &mut self,
        transactions: Vec<Transaction>,
        block_hash: [u8; HASH_SIZE],
        merkle_root_hash: [u8; HASH_SIZE],
    ) -> Result<(), String> {
        let (mf, root) = MerkleForest::new_complete_from_leafs(transactions.clone())?;
        if root != merkle_root_hash {
            return Err(format!("Creating merkle tree from transactions does not result in correct root, expected {:?} got {:?}", root, block_hash));
        }
        let coin_base_transaction_hash = mf.get_left_most_leaf(merkle_root_hash)?.hash();

        println!("OCT: {}", self.off_chain_transactions.len());
        println!("TRN: {}", transactions.len());

        let mut spent_outputs: Vec<([u8; HASH_SIZE], usize)> = Vec::new();
        for transaction in transactions.iter() {
            let transaction_hash = transaction.hash();
            if transaction.is_coin_base_transaction()
                && transaction.hash() != coin_base_transaction_hash
            {
                return Err(format!(
                    "Got wrong right most transaction, expected {} got {}",
                    hex::encode(coin_base_transaction_hash),
                    hex::encode(transaction.hash())
                ));
            } else if !transaction.is_id_base_transaction() {
                for (index, output) in transaction.get_outputs().iter().enumerate() {
                    let pk = output.pk;
                    if !self.unspent_outputs.contains_key(&pk)
                        || !self.unspent_outputs[&pk].contains_key(&(
                            block_hash,
                            transaction_hash,
                            TransactionVarUint::from(index),
                        ))
                    {
                        if self.blockchain.blocks.len() > 1 {
                            return Err(format!(
                            "Transaction with hash 0x{} on block 0x{}; trying to double-spend at index {}",
                            hex::encode(transaction_hash), hex::encode(block_hash), index
                        ));
                        }
                    }
                }
            }
        }
        for transaction in transactions.iter() {
            let transaction_hash = transaction.hash();
            for (i, output) in transaction.get_outputs().iter().enumerate() {
                let index = TransactionVarUint::from(i);
                let key = (block_hash, transaction_hash, index);
                if !self.unspent_outputs.contains_key(&output.pk) {
                    self.unspent_outputs.insert(output.pk, HashMap::new());
                }
                self.unspent_outputs
                    .get_mut(&output.pk)
                    .unwrap()
                    .insert(key, output.clone());
            }
            self.root_lookup.insert(transaction_hash, block_hash);
            for input in transaction.get_inputs() {
                spent_outputs.push((input.transaction_hash, input.index.get_value()));
            }
        }

        self.blockchain_merkle_forest
            .add_transactions(transactions)?;
        self.blockchain_merkle_forest
            .add_branches(mf.branches.values().cloned().collect::<Vec<Node>>())?;

        // self.unspent_outputs
        //     .retain(|(_, transaction_hash, index), _| {
        //         !spent_outputs
        //             .iter()
        //             .any(|(tx, i)| transaction_hash == tx && index.get_value() == *i)
        //     });

        Ok(())
    }

    pub fn convert_serialized_transactions(data: &[u8]) -> Result<Vec<Transaction>, String> {
        let mut transactions = Vec::new();
        let mut i = 0;
        while i < data.len() {
            let pre_i = i;
            let mut hash = [0; 32];
            hash.copy_from_slice(Sha3_256::digest(&data[pre_i..i]).as_slice());
            transactions.push(*Transaction::from_serialized(&data, &mut i)?);
        }
        Ok(transactions)
    }

    pub fn add_block(&mut self, block: Block) -> Result<[u8; HASH_SIZE], String> {
        self.blockchain.add_block(block)
    }

    pub fn contains_block(&mut self, hash: [u8; HASH_SIZE]) -> bool {
        self.blockchain.contains_block(hash)
    }

    pub fn add_serialized_blocks(
        &mut self,
        serialized_blocks: Vec<u8>,
        serialized_leafs: Vec<Vec<u8>>,
    ) -> Result<(), String> {
        let mut hash: Vec<u8> = BlockHash::default().hash().to_vec();
        let mut tmp_blocks = Vec::new();
        let mut i = 0;
        for serialized_tree_leafs in serialized_leafs {
            let mut leafs = Vec::new();
            let mut j = 0;
            while j < serialized_tree_leafs.len() {
                leafs.push(*Transaction::from_serialized(
                    &serialized_tree_leafs,
                    &mut j,
                )?);
            }
            let block = *Block::from_serialized(&serialized_blocks, &mut i)?;
            let block_len = block.serialized_len();
            if block.back_hash.hash().to_vec() == hash {
                hash = Sha3_256::digest(&serialized_blocks[i - block_len..i]).to_vec();
                if !BlockHash::contains_enough_work(&hash) {
                    return Err(format!(
                        "Wallet - Block with len {} at byte {} with magic {}, hashes to {:x?}, which does not represent enough work",
                        block_len, i - block_len, block.magic, hash
                    ));
                }
                tmp_blocks.push((block, leafs));
            } else {
                return Err(format!(
                    "Block with len {} at byte {} in chain has wrong back hash. Expected {:x?} got {}",
                    block_len,
                    i - block_len,
                    hash,
                    block.back_hash
                ));
            }
        }
        for (block, transactions) in tmp_blocks {
            self.add_on_chain_transactions(transactions, block.hash(), block.merkle_root.hash())?;
            // DO NOT CHANGE ORDER!!! Transactions have to be verified before adding block!
            self.blockchain.add_block(block)?;
        }
        Ok(())
    }

    pub fn get_pk(&self) -> Result<PublicKey, String> {
        match self.pk {
            Some(pk) => Ok(pk),
            None => Err(String::from("Public key not initialized")),
        }
    }

    pub fn get_sk(&self) -> Result<SecretKey, String> {
        match self.sk {
            Some(sk) => Ok(sk),
            None => Err(String::from("Public key not initialized")),
        }
    }

    pub fn get_serialized_blockchain(&self, n: usize) -> Result<(Vec<u8>, Vec<Vec<u8>>), String> {
        if self.is_block_miner {
            let mut buffer = vec![0; self.blockchain.serialized_len()];
            let merkle_roots = self.blockchain.serialize_n_blocks(&mut buffer, &mut 0, n)?;
            let mut serialized_tree_leafs = Vec::new();
            for merkle_root in merkle_roots {
                let (_, transactions) =
                    self.blockchain_merkle_forest.get_merkle_tree(merkle_root)?;
                let mut serialized_transactions = Vec::new();
                for transaction in transactions {
                    let mut serialized_transaction = vec![0; transaction.serialized_len()];
                    transaction.serialize_into(&mut serialized_transaction, &mut 0)?;
                    serialized_transactions.append(&mut serialized_transaction);
                }
                serialized_tree_leafs.push(serialized_transactions);
            }
            Ok((buffer, serialized_tree_leafs))
        } else {
            Err(String::from("Wallet not instantiated as miner, so the needed data to share blockchain data has not been saved"))
        }
    }

    fn mine_data(
        &self,
        n_par_workers: u64,
        par_work: u64,
        serialized_data: &mut Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        let mut i = 0;
        self.thread_pool.install(|| loop {
            let list: Vec<u64> = (0..n_par_workers).collect();
            match list.par_iter().find_map_any(|&j| {
                let start = i + j * par_work;
                let end = i + (j + 1) * par_work - 1;
                let mut miner = Miner::new_ranged(serialized_data.to_vec(), start..end).unwrap();
                while miner.do_work().is_pending() {}
                match miner.do_work() {
                    Poll::Ready(data) => data,
                    Poll::Pending => None,
                }
            }) {
                Some(r) => break Ok(r),
                None => i += n_par_workers * par_work,
            }
        })
    }

    pub fn mine_transaction(
        &self,
        n_par_workers: u64,
        par_work: u64,
        mut transaction: Transaction,
    ) -> Result<Transaction, String> {
        let mut serialized_transaction = vec![0u8; transaction.serialized_len()];
        transaction.serialize_into(&mut serialized_transaction, &mut 0)?;
        let mut hash = [0; 32];
        hash.copy_from_slice(&Sha3_256::digest(
            &serialized_transaction
                [0..serialized_transaction.len() - transaction.magic_serialized_len()],
        ));
        let data = self.mine_data(n_par_workers, par_work, &mut hash.to_vec())?;
        transaction.magic = TransactionVarUint {
            value: data[HASH_SIZE..].to_vec(),
        };
        Ok(transaction)
    }

    pub fn mine_block(
        &self,
        n_par_workers: u64,
        par_work: u64,
        block: Block,
    ) -> Result<Box<Block>, String> {
        let mut serialized_block = vec![0u8; block.serialized_len()];
        block.serialize_into(&mut serialized_block, &mut 0)?;
        self.mine_data(n_par_workers, par_work, &mut serialized_block)?;
        let data = self.mine_data(
            n_par_workers,
            par_work,
            &mut serialized_block[0..serialized_block.len() - block.magic.serialized_len()]
                .to_vec(),
        )?;
        Block::from_serialized(&data, &mut 0)
    }

    pub fn generate_init_blockchain(is_block_miner: bool) -> Result<Wallet, String> {
        let (pk, sk) = Wallet::generate_ec_keys();

        let my_value = TransactionValue::new_coin_transfer(u128::MAX, 0)?;

        let mut wallet = Wallet::new(pk, sk, is_block_miner)?;
        let message = b"Hello, World!";
        let mut padded_message = [0u8; transaction::BASE_TRANSACTION_MESSAGE_LEN];
        padded_message[0..13].copy_from_slice(message);

        // The first (and only) coin base transaction. Block 0 creating all value in Celestium. Ever
        let mut t0 = Transaction::new_coin_base_transaction(
            [0u8; 32],
            padded_message,
            TransactionOutput::new(my_value.clone(), pk),
        );

        print!("Starting mining T0... ");
        io::stdout().flush().unwrap();
        let start = Instant::now();
        t0 = wallet.mine_transaction(DEFAULT_N_THREADS, DEFAULT_PAR_WORK, t0)?;
        println!("Done! {:?}", start.elapsed());

        let pure_value = 30_000_000_000_000_000_000_000_000_000_000;
        let value = TransactionValue::new_coin_transfer(pure_value, 0)?;
        let mut outputs = vec![];

        let output_count = 11_000_000;
        for _ in (0..output_count).progress() {
            outputs.push(TransactionOutput::new(value.clone(), pk));
        }
        outputs.push(TransactionOutput::new(
            TransactionValue::new_coin_transfer(u128::MAX - pure_value * output_count as u128, 0)?,
            pk,
        ));

        let mut t1 = Transaction::new(
            vec![TransactionInput::new(
                [0u8; HASH_SIZE],
                t0.hash(),
                TransactionVarUint::from(0),
            )],
            outputs,
        )?;

        t1.sign(sk, 0)?;

        print!("Starting mining T1... ");
        io::stdout().flush().unwrap();
        let start = Instant::now();
        t1 = wallet.mine_transaction(DEFAULT_N_THREADS, DEFAULT_PAR_WORK, t1)?;
        println!("Done! {:?}", start.elapsed());

        let (_, merkle_root_hash) =
            MerkleForest::new_complete_from_leafs(vec![t0.clone(), t1.clone()])?;

        let block = Block::new(
            BlockVersion::default(),
            BlockHash::from(merkle_root_hash),
            *BlockHash::from_serialized(&[0u8; HASH_SIZE], &mut 0)?,
            TransactionVarUint::from(0),
        );

        print!("Starting mining B0... ");
        io::stdout().flush().unwrap();
        let start = Instant::now();
        let done_block = *wallet.mine_block(DEFAULT_N_THREADS, DEFAULT_PAR_WORK, block)?;
        println!("Done! {:?}", start.elapsed());

        let block_hash = done_block.hash();
        wallet.add_block(done_block)?;
        wallet.add_on_chain_transactions(vec![t0, t1], block_hash, merkle_root_hash)?;
        Ok(wallet)
    }

    // pub fn mine_until_complete(miner: &mut Miner) -> Option<Block> {
    //     loop {
    //         match miner.do_work() {
    //             Poll::Ready(result) => return result,
    //             Poll::Pending => {}
    //         }
    //     }
    // }

    pub fn generate_ec_keys_with_rng(rng: &mut ThreadRng) -> (PublicKey, SecretKey) {
        let secp = Secp256k1::new();
        let (sk, pk) = secp.generate_keypair(rng);
        (pk, sk)
    }

    pub fn generate_ec_keys() -> (PublicKey, SecretKey) {
        let secp = Secp256k1::new();
        let mut rng = rand::rngs::ThreadRng::default();
        let (sk, pk) = secp.generate_keypair(&mut rng);
        (pk, sk)
    }
}
