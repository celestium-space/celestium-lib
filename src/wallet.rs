use crate::{
    block::Block,
    block_hash::BlockHash,
    block_version::BlockVersion,
    blockchain::Blockchain,
    ec_key_serialization::PUBLIC_KEY_COMPRESSED_SIZE,
    miner::Miner,
    serialize::{DynamicSized, Serialize, StaticSized},
    transaction::{self, Transaction},
    transaction_hash::TransactionHash,
    transaction_input::TransactionInput,
    transaction_output::TransactionOutput,
    transaction_value::TransactionValue,
    transaction_varuint::TransactionVarUint,
};
use indexmap::IndexMap;
use indicatif::{ProgressBar, ProgressIterator, ProgressStyle};
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

pub const HASH_SIZE: usize = 32;
pub const DEFAULT_N_THREADS: u64 = 0x16;
pub const DEFAULT_PAR_WORK: u64 = 0x200000;
pub const DEFAULT_PROGRESSBAR_TEMPLATE: &str =
    "{msg} [{elapsed_precise}] [{wide_bar}] {pos}/{len} [{eta_precise}]";

pub struct BinaryWallet {
    pub blockchain_bin: Vec<u8>,
    pub pk_bin: Vec<u8>,
    pub sk_bin: Vec<u8>,
    pub on_chain_transactions_bin: Vec<u8>,
    pub unspent_outputs_bin: Vec<u8>,
    pub nft_lookups_bin: Vec<u8>,
    pub off_chain_transactions_bin: Vec<u8>,
}

pub type NFTHash = [u8; HASH_SIZE];
pub type OutputIndex = TransactionVarUint;

/// A Wallet is the interface used to interact with the blockchain.
///
pub struct Wallet {
    blockchain: Blockchain,
    pk: Option<PublicKey>,
    sk: Option<SecretKey>,
    pub on_chain_transactions: HashMap<BlockHash, IndexMap<TransactionHash, Transaction>>,
    pub unspent_outputs:
        HashMap<PublicKey, HashMap<(BlockHash, TransactionHash, OutputIndex), TransactionOutput>>,
    nft_lookup: HashMap<NFTHash, (PublicKey, BlockHash, TransactionHash, OutputIndex)>,
    pub off_chain_transactions: IndexMap<TransactionHash, Transaction>,
    pub thread_pool: ThreadPool,
}

impl Wallet {
    pub fn new_with_treadpool(
        pk: PublicKey,
        sk: SecretKey,
        thread_pool: ThreadPool,
    ) -> Result<Self, String> {
        Ok(Wallet {
            blockchain: Blockchain::new(Vec::new()),
            pk: Some(pk),
            sk: Some(sk),
            on_chain_transactions: HashMap::new(),
            unspent_outputs: <HashMap<
                PublicKey,
                HashMap<(BlockHash, TransactionHash, OutputIndex), TransactionOutput>,
            >>::new(),
            nft_lookup: HashMap::new(),
            off_chain_transactions: IndexMap::new(),
            thread_pool,
        })
    }

    pub fn new(pk: PublicKey, sk: SecretKey) -> Result<Self, String> {
        Wallet::new_with_treadpool(
            pk,
            sk,
            ThreadPoolBuilder::new()
                .num_threads(DEFAULT_N_THREADS as usize)
                .build()
                .unwrap(),
        )
    }

    fn serialize_transactions(transactions: &[Transaction]) -> Result<Vec<u8>, String> {
        let mut length = 0;
        for transaction in transactions {
            length += transaction.serialized_len();
        }
        let mut serialized_transactions = vec![0u8; length];

        let mut i = 0;
        for transaction in transactions {
            transaction.serialize_into(&mut serialized_transactions, &mut i)?;
        }
        Ok(serialized_transactions)
    }

    pub fn from_binary(
        binary_wallet: &BinaryWallet,
        reload_unspent_outputs: bool,
        reload_nft_lookups: bool,
        ignore_off_chain_transactions: bool,
    ) -> Result<Self, String> {
        let pk = *PublicKey::from_serialized(&binary_wallet.pk_bin, &mut 0)?;
        let blockchain = *Blockchain::from_serialized(&binary_wallet.blockchain_bin, &mut 0)?;
        let mut on_chain_transactions = HashMap::new();

        let mut i = 0;
        while i < binary_wallet.on_chain_transactions_bin.len() {
            let block_hash =
                *BlockHash::from_serialized(&binary_wallet.on_chain_transactions_bin, &mut i)?;
            let transaction_count = TransactionVarUint::from_serialized(
                &binary_wallet.on_chain_transactions_bin,
                &mut i,
            )?
            .get_value();
            let mut transactions = IndexMap::new();
            for _ in 0..transaction_count {
                let transaction = *Transaction::from_serialized(
                    &binary_wallet.on_chain_transactions_bin,
                    &mut i,
                )?;
                transactions.insert(transaction.hash()?, transaction);
            }
            on_chain_transactions.insert(block_hash, transactions);
        }

        let mut i = 0;
        let mut off_chain_transactions = IndexMap::new();
        if !ignore_off_chain_transactions {
            while i < binary_wallet.off_chain_transactions_bin.len() {
                let transaction = *Transaction::from_serialized(
                    &binary_wallet.off_chain_transactions_bin,
                    &mut i,
                )?;
                off_chain_transactions.insert(transaction.hash()?, transaction);
            }
        }

        let mut unspent_outputs: HashMap<
            PublicKey,
            HashMap<(BlockHash, TransactionHash, OutputIndex), TransactionOutput>,
        > = HashMap::new();
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
                    let pb = ProgressBar::with_message(
                        ProgressBar::new(output_count as u64),
                        format!(
                            "Loading big PK [0x{}...] (probably block zero)",
                            hex::encode(&pk.serialize()[..8])
                        ),
                    );
                    pb.set_style(
                        ProgressStyle::default_bar().template(DEFAULT_PROGRESSBAR_TEMPLATE),
                    );
                    Some(pb)
                } else {
                    None
                };
                for _ in 0..output_count {
                    let block_hash =
                        *BlockHash::from_serialized(&binary_wallet.unspent_outputs_bin, &mut i)?;
                    let transaction_hash = *TransactionHash::from_serialized(
                        &binary_wallet.unspent_outputs_bin,
                        &mut i,
                    )?;

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
                (BlockHash, TransactionHash, OutputIndex),
                TransactionOutput,
                RandomState,
            > = HashMap::new();

            for (block_hash, transactions) in on_chain_transactions.iter() {
                for (_, transaction) in transactions {
                    let outputs = transaction.get_outputs();
                    let pb = if outputs.len() > 100_000 {
                        let pb = ProgressBar::with_message(
                            ProgressBar::new(outputs.len() as u64),
                            format!(
                                "Loading big PK [0x{}...] (probably block zero)",
                                hex::encode(&pk.serialize()[..8])
                            ),
                        );
                        pb.set_style(
                            ProgressStyle::default_bar().template(DEFAULT_PROGRESSBAR_TEMPLATE),
                        );
                        Some(pb)
                    } else {
                        None
                    };
                    let transaction_hash = transaction.hash()?;
                    for (i, output) in outputs.iter().enumerate() {
                        tmp_unspent_outputs.insert(
                            (
                                block_hash.clone(),
                                transaction_hash.clone(),
                                TransactionVarUint::from(i),
                            ),
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
                for (_, transaction) in transactions {
                    if !transaction.is_base_transaction() {
                        for (i, input) in transaction.get_inputs().into_iter().enumerate() {
                            let input_block_hash = if !input.block_hash.is_zero_block() {
                                input.block_hash.clone()
                            } else {
                                block_hash.clone()
                            };
                            if tmp_unspent_outputs
                                .remove(&(
                                    input_block_hash,
                                    input.transaction_hash.clone(),
                                    input.output_index.clone(),
                                ))
                                .is_none()
                            {
                                return Err(format!(
                                    "Input {} on transaction {} is trying to spend non-existing or already spent output {} at index {} on block {}", 
                                    i, transaction.hash()?, input.output_index, input.transaction_hash, input.block_hash
                                ));
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
                                BlockHash::from([0u8; HASH_SIZE]),
                                transaction.hash()?,
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
                            if tmp_unspent_outputs
                                .remove(&(
                                    input.block_hash,
                                    input.transaction_hash,
                                    input.output_index,
                                ))
                                .is_none()
                            {
                                panic!("ERROR");
                            }
                        }
                    }
                }
            }

            for (key, output) in tmp_unspent_outputs {
                unspent_outputs
                    .entry(output.pk)
                    .or_insert_with(HashMap::new);
                let pk_outputs = unspent_outputs.get_mut(&output.pk).unwrap();
                pk_outputs.insert(key, output);
            }
        }

        let mut i = 0;
        let mut nft_lookup = HashMap::new();
        if !reload_nft_lookups {
            while i < binary_wallet.nft_lookups_bin.len() {
                let mut nft_hash: [u8; HASH_SIZE] = [0u8; HASH_SIZE];
                nft_hash.copy_from_slice(&binary_wallet.nft_lookups_bin[i..i + HASH_SIZE]);
                i += HASH_SIZE;
                let pk = *PublicKey::from_serialized(&binary_wallet.nft_lookups_bin, &mut i)?;
                let block_hash =
                    *BlockHash::from_serialized(&binary_wallet.nft_lookups_bin, &mut i)?;
                let transaction_hash =
                    *TransactionHash::from_serialized(&binary_wallet.nft_lookups_bin, &mut i)?;
                nft_lookup.insert(
                    nft_hash,
                    (
                        pk,
                        block_hash,
                        transaction_hash,
                        *TransactionVarUint::from_serialized(
                            &binary_wallet.nft_lookups_bin,
                            &mut i,
                        )?,
                    ),
                );
            }
        } else {
            println!("Reloading NFT lookups from unspent outputs");
            for (pk, pk_unspent_outputs) in unspent_outputs.iter() {
                let output_count = pk_unspent_outputs.len();
                let pb = if output_count > 100_000 {
                    let pb = ProgressBar::with_message(
                        ProgressBar::new(output_count as u64),
                        format!(
                            "Loading big PK [0x{}...] (probably block zero)",
                            hex::encode(&pk.serialize()[..8])
                        ),
                    );
                    pb.set_style(
                        ProgressStyle::default_bar().template(DEFAULT_PROGRESSBAR_TEMPLATE),
                    );
                    Some(pb)
                } else {
                    None
                };
                for ((bh, th, i), to) in pk_unspent_outputs {
                    if let Ok(id) = to.value.get_id() {
                        nft_lookup.insert(id, (*pk, bh.clone(), th.clone(), i.clone()));
                    }
                    if let Some(ref pb) = pb {
                        pb.inc(1);
                    }
                }
                if let Some(ref pb) = pb {
                    pb.finish();
                }
            }
        }

        let thread_pool = ThreadPoolBuilder::new()
            .num_threads(DEFAULT_N_THREADS as usize)
            .build()
            .unwrap();

        Ok(Wallet {
            blockchain,
            pk: Some(pk),
            sk: Some(*SecretKey::from_serialized(&binary_wallet.sk_bin, &mut 0)?),
            on_chain_transactions,
            unspent_outputs,
            nft_lookup,
            off_chain_transactions,
            thread_pool,
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

                let on_chain_transactions_bin_len =
                    self.on_chain_transactions
                        .values()
                        .fold(0, |sum, transactions| {
                            sum + BlockHash::serialized_len()
                                + TransactionVarUint::from(transactions.len()).serialized_len()
                                + transactions
                                    .iter()
                                    .fold(0, |sum, (_, t)| sum + t.serialized_len())
                        });
                let mut on_chain_transactions_bin = vec![0u8; on_chain_transactions_bin_len];
                let mut i = 0;
                for (block_hash, transactions) in &self.on_chain_transactions {
                    block_hash.serialize_into(&mut on_chain_transactions_bin, &mut i)?;
                    TransactionVarUint::from(transactions.len())
                        .serialize_into(&mut on_chain_transactions_bin, &mut i)?;
                    for (_, transaction) in transactions {
                        transaction.serialize_into(&mut on_chain_transactions_bin, &mut i)?;
                    }
                }

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
                            BlockHash::serialized_len()
                                + TransactionHash::serialized_len()
                                + index.serialized_len()
                                + output.serialized_len()
                        ];
                        let mut i = 0;
                        block_hash.serialize_into(&mut unspent_output_bin, &mut i)?;
                        transaction_hash.serialize_into(&mut unspent_output_bin, &mut i)?;
                        index.serialize_into(&mut unspent_output_bin, &mut i)?;
                        output.serialize_into(&mut unspent_output_bin, &mut i)?;
                        unspent_outputs_bin.append(&mut unspent_output_bin);
                    }
                }

                let mut nft_lookups_bin = Vec::new();
                for nft_lookup in self.nft_lookup.iter() {
                    let (nft_hash, (pk, block_hash, transaction_hash, index)) = nft_lookup;
                    let mut nft_lookup_bin = vec![
                        0u8;
                        nft_hash.len()
                            + PublicKey::serialized_len()
                            + BlockHash::serialized_len()
                            + TransactionHash::serialized_len()
                            + index.serialized_len()
                    ];
                    let mut i = 0;
                    nft_lookup_bin[i..i + HASH_SIZE].copy_from_slice(nft_hash);
                    i += HASH_SIZE;
                    pk.serialize_into(&mut nft_lookup_bin, &mut i)?;
                    block_hash.serialize_into(&mut nft_lookup_bin, &mut i)?;
                    transaction_hash.serialize_into(&mut nft_lookup_bin, &mut i)?;
                    index.serialize_into(&mut nft_lookup_bin, &mut i)?;
                    nft_lookups_bin.append(&mut nft_lookup_bin);
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
                    on_chain_transactions_bin,
                    unspent_outputs_bin,
                    nft_lookups_bin,
                    off_chain_transactions_bin,
                })
            }
            _ => Err(String::from(
                "Wallet must have both public key and secret key to send money",
            )),
        }
    }

    pub fn serialize_blockchain(&self) -> Result<Vec<u8>, String> {
        let mut serialized_blocks = vec![0u8; self.blockchain.serialized_len()];
        self.blockchain
            .serialize_into(&mut serialized_blocks, &mut 0)?;
        Ok(serialized_blocks)
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

    pub fn get_balance(
        &self,
        pk: PublicKey,
    ) -> Result<
        (
            u128,
            Vec<(TransactionInput, TransactionValue)>,
            Vec<(TransactionInput, TransactionValue)>,
        ),
        String,
    > {
        let mut dust_gathered = 0;
        let mut owned_base_ids = Vec::new();
        let mut owned_transferred_ids = Vec::new();
        for ((bh, th, i), transaction_output) in
            self.unspent_outputs.get(&pk).unwrap_or(&HashMap::new())
        {
            if transaction_output.pk == pk {
                let transaction = if bh == &BlockHash::from([0u8; HASH_SIZE]) {
                    self.off_chain_transactions.get(th).unwrap()
                } else {
                    self.on_chain_transactions
                        .get(&bh)
                        .unwrap()
                        .get(th)
                        .unwrap()
                };
                if transaction_output.value.is_coin_transfer() {
                    dust_gathered += transaction_output.value.get_value().unwrap();
                } else if transaction.is_base_transaction() {
                    owned_base_ids.push((
                        TransactionInput::new(bh.clone(), th.clone(), i.clone()),
                        transaction_output.value.clone(),
                    ));
                } else {
                    owned_transferred_ids.push((
                        TransactionInput::new(bh.clone(), th.clone(), i.clone()),
                        transaction_output.value.clone(),
                    ));
                }
            }
        }
        Ok((dust_gathered, owned_base_ids, owned_transferred_ids))
    }

    #[allow(clippy::type_complexity)]
    pub fn collect_for_coin_transfer(
        &self,
        value: &TransactionValue,
        pk: PublicKey,
        black_list: HashSet<(TransactionHash, usize)>,
    ) -> Result<(u128, Vec<TransactionInput>), String> {
        let mut dust_gathered = 0;
        let mut inputs = Vec::new();
        if let Some(pk_unspent_outputs) = self.unspent_outputs.get(&pk) {
            for ((block_hash, transaction_hash, index), transaction_output) in pk_unspent_outputs {
                if black_list.contains(&(transaction_hash.clone(), index.get_value())) {
                    continue;
                }
                if transaction_output.pk == pk
                    && transaction_output.value.is_coin_transfer()
                    && transaction_output.value.get_value()? > 0
                {
                    let input = TransactionInput::new(
                        block_hash.clone(),
                        transaction_hash.clone(),
                        index.clone(),
                    );
                    inputs.push(input);
                    dust_gathered += transaction_output.value.get_value()?;
                    if dust_gathered >= value.get_value()? + value.get_fee()? {
                        break;
                    }
                }
            }
        }
        Ok((dust_gathered, inputs))
    }

    pub fn verify_off_chain_transaction(
        &self,
        transaction: &Transaction,
    ) -> Result<Vec<(PublicKey, (BlockHash, TransactionHash, TransactionVarUint))>, String> {
        if transaction.is_id_base_transaction() {
            let id = transaction.get_outputs()[0].value.get_id()?;
            if self.nft_lookup.get(&id).is_some() {
                return Err(format!(
                    "ID [0x{}] already exists on blockchain",
                    hex::encode(id)
                ));
            }
        }

        let pks = transaction.verify_transaction(
            &self.off_chain_transactions,
            &self.on_chain_transactions,
            &self.unspent_outputs,
        )?;

        let mut actual_inputs = Vec::new();
        if transaction.is_base_transaction() {
            let base_transaction_input_block_hash = transaction.get_inputs()[0].block_hash.clone();
            let current_blockchain_head_hash = self.get_head_hash();
            if base_transaction_input_block_hash != current_blockchain_head_hash {
                return Err(format!(
                    "Base transaction input block hash {} does not match head block hash {}",
                    base_transaction_input_block_hash, current_blockchain_head_hash
                ));
            }
        } else {
            for input in transaction.get_inputs() {
                let mut actual_input = None;
                for pk in pks.iter() {
                    let output_ref = (
                        input.block_hash.clone(),
                        input.transaction_hash.clone(),
                        input.output_index.clone(),
                    );
                    if self
                        .unspent_outputs
                        .get(&pk)
                        .unwrap_or(&HashMap::new())
                        .contains_key(&output_ref)
                    {
                        actual_input = Some((*pk, output_ref.clone()));
                        break;
                    }
                }
                if let Some(actual_input) = actual_input {
                    actual_inputs.push(actual_input);
                } else {
                    return Err(format!(
                        "({}, {}, {}), does not refer to an unspent output",
                        input.transaction_hash,
                        input.block_hash,
                        input.output_index.clone().get_value(),
                    ));
                }
            }
        }
        Ok(actual_inputs)
    }

    pub fn add_off_chain_transaction(&mut self, transaction: &Transaction) -> Result<(), String> {
        let actual_inputs = self.verify_off_chain_transaction(transaction)?;

        for (pk, output_ref) in actual_inputs {
            let pk_unspent_outputs = self.unspent_outputs.get_mut(&pk).unwrap();
            let unspent_output = pk_unspent_outputs.get(&output_ref).unwrap();

            if unspent_output.value.is_id_transfer()
                && self
                    .nft_lookup
                    .remove(&unspent_output.value.get_id()?)
                    .is_none()
            {
                println!("WARNING: NFT Lookup table out of sync with Unspent Outputs!")
            }
            if pk_unspent_outputs.remove(&output_ref).is_none() {
                println!("WARNING: Could not remove spent output {} on transaction {} on block {} from unspent outputs", output_ref.0, output_ref.1, output_ref.2)
            };
            if self.unspent_outputs[&pk].is_empty() {
                self.unspent_outputs.remove(&pk);
            }
        }

        for (index, output) in transaction.get_outputs().iter().enumerate() {
            let pk = output.pk;
            self.unspent_outputs.entry(pk).or_insert_with(HashMap::new);
            self.unspent_outputs.get_mut(&pk).unwrap().insert(
                (
                    BlockHash::from([0u8; HASH_SIZE]),
                    transaction.hash()?,
                    TransactionVarUint::from(index),
                ),
                output.clone(),
            );
            if output.value.is_id_transfer() {
                self.nft_lookup.insert(
                    output.value.get_id()?,
                    (
                        pk,
                        BlockHash::from([0u8; HASH_SIZE]),
                        transaction.hash()?,
                        TransactionVarUint::from(index),
                    ),
                );
            }
        }

        self.off_chain_transactions
            .insert(transaction.hash()?, transaction.clone());
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
            self.add_off_chain_transaction(&transaction)?;
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
                for (_, block_transactions) in &self.on_chain_transactions {
                    for hash in block_transactions.keys() {
                        if self.off_chain_transactions.contains_key(hash) {
                            return Err(format!(
                                "Off chain transaction {} already on blockchain",
                                hash
                            ));
                        }
                    }
                }

                let mut total_fee = 0;
                let mut transactions = Vec::new();
                for transaction in self.off_chain_transactions.values() {
                    total_fee += transaction.get_total_fee();
                    transactions.push(transaction.clone());
                }
                transactions.push(Wallet::mine_transaction(
                    DEFAULT_N_THREADS,
                    DEFAULT_PAR_WORK,
                    Transaction::new_coin_base_transaction(
                        self.get_head_hash(),
                        [0u8; transaction::BASE_TRANSACTION_MESSAGE_LEN],
                        TransactionOutput::new(
                            TransactionValue::new_coin_transfer(total_fee, 0)?,
                            pk,
                        ),
                    )?,
                    &self.thread_pool,
                )?);
                let back_hash = self.blockchain.get_head_hash();
                let magic = TransactionVarUint::from(0);
                let version = BlockVersion::default();
                let mut block_hash_bin = [0u8; HASH_SIZE];
                block_hash_bin.copy_from_slice(&Sha3_256::digest(&Wallet::serialize_transactions(
                    &transactions,
                )?));
                let block = Block::new(version, BlockHash::from(block_hash_bin), back_hash, magic);
                Ok((block, transactions))
            }
            None => Err(String::from("Need public key to mine")),
        }
    }

    pub fn get_head_hash(&self) -> BlockHash {
        self.blockchain.get_head_hash()
    }

    pub fn add_on_chain_transactions(
        &mut self,
        transactions: Vec<Transaction>,
        block_hash: BlockHash,
        block_transactions_hash: [u8; HASH_SIZE],
    ) -> Result<(), String> {
        if self.on_chain_transactions.contains_key(&block_hash) {
            return Err(format!(
                "On chain transactions already added for block {}",
                block_hash
            ));
        }

        let transactions_hash = Sha3_256::digest(&Wallet::serialize_transactions(&transactions)?);
        if transactions_hash.as_slice() != block_transactions_hash {
            return Err(format!("Hashing serialized transactions does not result in the hash denoted by the block, expected {:?} got {:?}", block_transactions_hash, transactions_hash));
        }
        let coin_base_transaction_hash = transactions.last().unwrap().hash().unwrap();

        let mut spent_outputs = Vec::new();
        for transaction in transactions.iter() {
            let transaction_hash = transaction.hash()?;
            if transaction.is_coin_base_transaction()
                && transaction.hash()? != coin_base_transaction_hash
            {
                return Err(format!(
                    "Got wrong right most transaction, expected {} got {}",
                    coin_base_transaction_hash,
                    transaction.hash()?
                ));
            } else if !transaction.is_id_base_transaction() {
                for (index, output) in transaction.get_outputs().iter().enumerate() {
                    let pk = output.pk;
                    if (!self.unspent_outputs.contains_key(&pk)
                        || !self.unspent_outputs[&pk].contains_key(&(
                            block_hash.clone(),
                            transaction_hash.clone(),
                            TransactionVarUint::from(index),
                        )))
                        && self.blockchain.blocks.len() > 1
                    {
                        return Err(format!(
                        "Transaction with hash {} on block {}; trying to double-spend at index {}",
                        transaction_hash, block_hash, index
                    ));
                    }
                }
            }
        }
        let mut transactions_indexmap = IndexMap::new();
        for transaction in transactions.iter() {
            let transaction_hash = transaction.hash()?;
            for (i, output) in transaction.get_outputs().iter().enumerate() {
                let index = TransactionVarUint::from(i);
                let key = (block_hash.clone(), transaction_hash.clone(), index);
                self.unspent_outputs
                    .entry(output.pk)
                    .or_insert_with(HashMap::new);
                self.unspent_outputs
                    .get_mut(&output.pk)
                    .unwrap()
                    .insert(key, output.clone());
            }
            for input in transaction.get_inputs() {
                spent_outputs.push((input.transaction_hash, input.output_index.get_value()));
            }
            transactions_indexmap.insert(transaction_hash.clone(), transaction.clone());
            self.off_chain_transactions.remove(&transaction_hash);
        }

        self.on_chain_transactions
            .insert(block_hash, transactions_indexmap);

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

    pub fn contains_block(&mut self, hash: BlockHash) -> bool {
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
            self.add_on_chain_transactions(
                transactions,
                block.hash(),
                block.transactions_hash.hash(),
            )?;
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

    pub fn mine_block_data(
        n_par_workers: u64,
        par_work: u64,
        serialized_data: &mut Vec<u8>,
        thread_pool: &ThreadPool,
    ) -> Result<Vec<u8>, String> {
        let mut i = 0;
        thread_pool.install(|| loop {
            let list: Vec<u64> = (0..n_par_workers).collect();
            match list.par_iter().find_map_any(|&j| {
                let start = i + j * par_work;
                let end = i + (j + 1) * par_work - 1;
                let mut miner = Miner::new_ranged(serialized_data.to_vec(), start..end).unwrap();
                while miner.do_block_work().is_pending() {}
                match miner.do_block_work() {
                    Poll::Ready(data) => data,
                    Poll::Pending => None,
                }
            }) {
                Some(r) => break Ok(r),
                None => i += n_par_workers * par_work,
            }
        })
    }
    pub fn mine_transaction_data(
        n_par_workers: u64,
        par_work: u64,
        serialized_data: &mut Vec<u8>,
        thread_pool: &ThreadPool,
    ) -> Result<Vec<u8>, String> {
        let mut i = 0;
        thread_pool.install(|| loop {
            let list: Vec<u64> = (0..n_par_workers).collect();
            match list.par_iter().find_map_any(|&j| {
                let start = i + j * par_work;
                let end = i + (j + 1) * par_work - 1;
                let mut miner = Miner::new_ranged(serialized_data.to_vec(), start..end).unwrap();
                while miner.do_transaction_work().is_pending() {}
                match miner.do_transaction_work() {
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
        n_par_workers: u64,
        par_work: u64,
        mut transaction: Transaction,
        thread_pool: &ThreadPool,
    ) -> Result<Transaction, String> {
        let mut serialized_transaction = vec![0u8; transaction.serialized_len()];
        transaction.serialize_into(&mut serialized_transaction, &mut 0)?;
        let mut hash = [0; 32];
        hash.copy_from_slice(&Sha3_256::digest(
            &serialized_transaction
                [0..serialized_transaction.len() - transaction.magic_serialized_len()],
        ));
        let data = Wallet::mine_transaction_data(
            n_par_workers,
            par_work,
            &mut hash.to_vec(),
            thread_pool,
        )?;
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
        Wallet::mine_block_data(
            n_par_workers,
            par_work,
            &mut serialized_block,
            &self.thread_pool,
        )?;
        let data = Wallet::mine_block_data(
            n_par_workers,
            par_work,
            &mut serialized_block[0..serialized_block.len() - block.magic.serialized_len()]
                .to_vec(),
            &self.thread_pool,
        )?;
        Block::from_serialized(&data, &mut 0)
    }

    pub fn generate_init_blockchain() -> Result<Wallet, String> {
        let (pk, sk) = Wallet::generate_ec_keys();

        let my_value = TransactionValue::new_coin_transfer(u128::MAX, 0)?;

        let mut wallet = Wallet::new(pk, sk)?;
        let message = b"Hello, World!";
        let mut padded_message = [0u8; transaction::BASE_TRANSACTION_MESSAGE_LEN];
        padded_message[0..13].copy_from_slice(message);

        // The first (and only) coin base transaction. Block 0 creating all value in Celestium. Ever
        let mut t0 = Transaction::new_coin_base_transaction(
            BlockHash::from([0u8; 32]),
            padded_message,
            TransactionOutput::new(my_value, pk),
        )?;

        print!("Starting mining T0... ");
        io::stdout().flush().unwrap();
        let start = Instant::now();
        t0 =
            Wallet::mine_transaction(DEFAULT_N_THREADS, DEFAULT_PAR_WORK, t0, &wallet.thread_pool)?;
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
                BlockHash::from([0u8; HASH_SIZE]),
                t0.hash()?,
                TransactionVarUint::from(0),
            )],
            outputs,
        )?;

        t1.sign(sk, 0)?;

        print!("Starting mining T1... ");
        io::stdout().flush().unwrap();
        let start = Instant::now();
        t1 =
            Wallet::mine_transaction(DEFAULT_N_THREADS, DEFAULT_PAR_WORK, t1, &wallet.thread_pool)?;
        println!("Done! {:?}", start.elapsed());

        let mut transactions_hash = [0u8; HASH_SIZE];
        transactions_hash.copy_from_slice(&Sha3_256::digest(&Wallet::serialize_transactions(&[
            t1.clone(),
            t0.clone(),
        ])?));

        let block = Block::new(
            BlockVersion::default(),
            BlockHash::from(transactions_hash),
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
        wallet.add_on_chain_transactions(vec![t1, t0], block_hash, transactions_hash)?;
        Ok(wallet)
    }

    pub fn count_nft_lookup(&self) -> usize {
        self.nft_lookup.len()
    }

    pub fn get_transaction(
        &self,
        block_hash: &BlockHash,
        transaction_hash: &TransactionHash,
    ) -> Option<&Transaction> {
        if block_hash.is_zero_block() {
            self.off_chain_transactions.get(transaction_hash)
        } else if let Some(b) = self.on_chain_transactions.get(&block_hash) {
            b.get(transaction_hash)
        } else {
            None
        }
    }

    pub fn lookup_nft(
        &self,
        nft_hash: [u8; HASH_SIZE],
    ) -> Option<(PublicKey, BlockHash, TransactionHash, TransactionVarUint)> {
        self.nft_lookup.get(&nft_hash).cloned()
    }

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
