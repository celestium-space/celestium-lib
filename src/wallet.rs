use crate::block_version::BlockVersion;
use crate::magic::Magic;
use crate::{
    block::Block,
    block_hash::BlockHash,
    blockchain::Blockchain,
    ec_key_serialization::PUBLIC_KEY_COMPRESSED_SIZE,
    merkle_forest::{MerkleForest, HASH_SIZE},
    miner::Miner,
    serialize::{DynamicSized, Serialize, StaticSized},
    transaction::Transaction,
    transaction_input::TransactionInput,
    transaction_output::TransactionOutput,
    transaction_value::TransactionValue,
    transaction_varuint::TransactionVarUint,
    transaction_version::TransactionVersion,
};
use secp256k1::Secp256k1;
use secp256k1::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::task::Poll;

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
    blockchain_merkle_forest: MerkleForest<Transaction>,
    unspent_outputs: Vec<(Transaction, TransactionVarUint)>,
    root_lookup: HashMap<[u8; HASH_SIZE], [u8; HASH_SIZE]>,
    off_chain_transactions: HashMap<[u8; HASH_SIZE], Transaction>,
    is_miner: bool,
}

impl Wallet {
    pub fn default(pk: PublicKey, sk: SecretKey) -> Self {
        Wallet {
            blockchain: Blockchain::new(Vec::new()),
            pk: Some(pk),
            sk: Some(sk),
            blockchain_merkle_forest: MerkleForest::new_empty(),
            unspent_outputs: Vec::new(),
            root_lookup: HashMap::new(),
            off_chain_transactions: HashMap::new(),
            is_miner: false,
        }
    }

    pub fn default_miner(pk: PublicKey, sk: SecretKey) -> Self {
        Wallet {
            blockchain: Blockchain::new(Vec::new()),
            pk: Some(pk),
            sk: Some(sk),
            blockchain_merkle_forest: MerkleForest::new_empty(),
            unspent_outputs: Vec::new(),
            root_lookup: HashMap::new(),
            off_chain_transactions: HashMap::new(),
            is_miner: true,
        }
    }

    pub fn from_binary(binary_wallet: &BinaryWallet, is_miner: bool) -> Result<Self, String> {
        let pk = *PublicKey::from_serialized(&binary_wallet.pk_bin, &mut 0)?;
        let blockchain = *Blockchain::from_serialized(&binary_wallet.blockchain_bin, &mut 0)?;
        let mut merkle_forest = MerkleForest::new_empty();
        merkle_forest.add_serialized_transactions(&binary_wallet.mf_leafs_bin, &mut 0)?;
        merkle_forest.add_serialized_nodes(&binary_wallet.mf_branches_bin)?;
        let mut i = 0;
        let mut unspent_outputs = Vec::new();
        while i < binary_wallet.unspent_outputs_bin.len() {
            unspent_outputs.push((
                *Transaction::from_serialized(&binary_wallet.unspent_outputs_bin, &mut i)?,
                *TransactionVarUint::from_serialized(&binary_wallet.unspent_outputs_bin, &mut i)?,
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
        let mut off_chain_transactions = HashMap::new();
        while i < binary_wallet.off_chain_transactions_bin.len() {
            let transaction =
                *Transaction::from_serialized(&binary_wallet.off_chain_transactions_bin, &mut i)?;
            off_chain_transactions.insert(transaction.hash(), transaction);
        }
        Ok(Wallet {
            blockchain,
            pk: Some(pk),
            sk: Some(*SecretKey::from_serialized(&binary_wallet.sk_bin, &mut 0)?),
            blockchain_merkle_forest: merkle_forest,
            unspent_outputs,
            root_lookup,
            off_chain_transactions,
            is_miner,
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
                for unspent_output in self.unspent_outputs.iter() {
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

    pub fn get_balance(&self) -> Result<u128, String> {
        match self.pk {
            Some(pk) => {
                let mut dust_gathered = 0;
                let cloned = self.unspent_outputs.clone();
                for (transaction, index) in cloned {
                    let transaction_output = transaction.get_output(&index);
                    if transaction_output.pk == pk && transaction_output.value.is_coin_transfer() {
                        dust_gathered += transaction_output.value.get_value().unwrap();
                    }
                }
                Ok(dust_gathered)
            }
            None => Err(String::from("Cannot get balance without public key")),
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
        let cloned = self.unspent_outputs.clone();
        // cloned.sort_by(|(a, _), (b, _)| { //TODO: Sort outputs by block index
        //     let block_a = self
        //         .blockchain
        //         .get_block_time(*self.root_lookup.get(&a.hash().unwrap()).unwrap())
        //         .unwrap();
        //     let block_b = self
        //         .blockchain
        //         .get_block_time(*self.root_lookup.get(&b.hash().unwrap()).unwrap())
        //         .unwrap();
        //     block_a.partial_cmp(&block_b).unwrap()
        // });

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
            let input = TransactionInput::from_transaction(transaction.clone(), index.clone());
            inputs.push(input)
        }
        Ok((dust_gathered, inputs, outputs))
    }

    pub fn add_off_chain_transaction(&mut self, transaction: Transaction) -> Result<(), String> {
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
            let (dust, inputs, used_outputs) = self.collect_for_coin_transfer(&value, from_pk)?;
            let change = dust - (value.get_value()? + value.get_fee()?);
            let mut outputs = vec![TransactionOutput::new(value, to_pk)];
            if change > 0 {
                outputs.push(TransactionOutput::new(
                    TransactionValue::new_coin_transfer(change, 0)?,
                    from_pk,
                ));
            }
            let mut transaction = Transaction::new(TransactionVersion::default(), inputs, outputs);
            for i in 0..transaction.inputs.len() {
                transaction.sign(from_sk, i)?;
            }
            let transaction_len = transaction.serialized_len();
            let mut serialized_transaction = vec![0u8; transaction_len];
            transaction.serialize_into(&mut serialized_transaction, &mut 0)?;
            self.add_off_chain_transaction(transaction)?;
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

    pub fn miner_from_off_chain_transactions(
        &self,
        //hash: [u8; HASH_SIZE],
        start: u64,
        end: u64,
    ) -> Result<Miner, String> {
        match self.pk {
            Some(pk) => {
                let mut total_fee = 0;
                let mut transactions = Vec::new();
                for transaction in self.off_chain_transactions.values() {
                    total_fee += transaction.get_total_fee();
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
                        TransactionOutput::new(
                            TransactionValue::new_id_transfer([0u8; HASH_SIZE])?,
                            pk,
                        ),
                    ],
                ));
                let mut merkle_forest = MerkleForest::new_empty();
                merkle_forest.add_transactions(transactions.clone())?;
                let merkle_root =
                    *BlockHash::from_serialized(&merkle_forest.create_tree_from_leafs()?, &mut 0)?;
                let back_hash =
                    *BlockHash::from_serialized(&self.blockchain.get_head_hash()?, &mut 0)?;
                Miner::new_from_hashes(merkle_root, back_hash, transactions, start, end)
            }
            None => Err(String::from("Need public key to mine")),
        }
    }

    pub fn add_on_chain_transactions(
        &mut self,
        transactions: Vec<Transaction>,
        block_hash: [u8; HASH_SIZE],
    ) -> Result<bool, String> {
        let mut spent_outputs: Vec<([u8; HASH_SIZE], usize)> = Vec::new();
        for transaction in transactions.iter() {
            self.off_chain_transactions.remove(&transaction.hash());
            for (i, _) in transaction.outputs.iter().enumerate() {
                //if self.pk.is_some() && self.pk.unwrap() == transaction_output.pk {
                self.root_lookup.insert(transaction.hash(), block_hash);
                self.unspent_outputs
                    .push((transaction.clone(), TransactionVarUint::from_usize(i)));
                //}
            }
            for input in transaction.inputs.iter() {
                spent_outputs.push((input.tx, input.index.get_value()));
            }
        }

        self.unspent_outputs
            .retain(|(unspent_output_transaction, index)| {
                !spent_outputs.iter().any(|(tx, i)| {
                    unspent_output_transaction.hash() == *tx && index.get_value() == *i
                })
            });
        self.blockchain_merkle_forest.add_transactions(transactions)
    }

    pub fn convert_serialized_transactions(data: &[u8]) -> Result<Vec<Transaction>, String> {
        let mut transactions = Vec::new();
        let mut i = 0;
        while i < data.len() {
            let pre_i = i;
            let mut hash = [0; 32];
            hash.copy_from_slice(Sha256::digest(&data[pre_i..i]).as_slice());
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
        let mut hash = BlockHash::default();
        let mut tmp_blocks = Vec::new();
        let mut tmp_merkle_forest = Vec::new();
        let mut i = 0;
        for serialized_tree_leafs in serialized_leafs {
            tmp_merkle_forest.push(MerkleForest::new_complete_from_serialized_leafs(
                serialized_tree_leafs,
            )?);
            let block = *Block::from_serialized(&serialized_blocks, &mut i)?;
            if block.back_hash == hash {
                let block_len = Block::serialized_len();
                hash = *BlockHash::from_serialized(
                    Sha256::digest(&serialized_blocks[i - block_len..i]).as_slice(),
                    &mut 0,
                )?;
                let valid_hash = hash.contains_enough_work();
                if !valid_hash {
                    return Err(format!(
                        "Block with len {} at byte {} with magic {}, hashes to {}, which does not represent enough work",
                        block_len, i - block_len, block.magic, hash
                    ));
                }
                tmp_blocks.push(block);
            } else {
                return Err(format!(
                    "Block at addr {} in chain has wrong back hash. Expected {} got {}",
                    i, hash, block.back_hash
                ));
            }
        }
        for block in tmp_blocks {
            self.blockchain.add_block(block)?;
        }
        for merkle_tree in tmp_merkle_forest {
            self.blockchain_merkle_forest.add_merkle_tree(merkle_tree)?;
        }
        Ok(())
    }

    pub fn get_pk(&self) -> Result<[u8; PUBLIC_KEY_COMPRESSED_SIZE], String> {
        match self.pk {
            Some(pk) => {
                let mut serialized_pk = [0u8; PUBLIC_KEY_COMPRESSED_SIZE];
                pk.serialize_into(&mut serialized_pk, &mut 0)?;
                Ok(serialized_pk)
            }
            None => Err(String::from("Public key not inititialized")),
        }
    }

    pub fn get_serialized_blockchain(&self, n: usize) -> Result<Vec<u8>, String> {
        let mut buffer = vec![0; Block::serialized_len() * n];
        self.blockchain.serialize_n_blocks(&mut buffer, &mut 0, n)?;
        Ok(buffer)
    }

    pub fn generate_init_blockchain(is_miner: bool) -> Result<Wallet, String> {
        let (pk1, sk1) = Wallet::generate_ec_keys();

        let my_value = TransactionValue::new_coin_transfer(10000, 0)?;
        let mut data_hash = [0u8; HASH_SIZE];
        data_hash.copy_from_slice(&Sha256::digest(b"Hello, World!"));
        let t0 = Transaction::new(
            TransactionVersion::default(),
            Vec::new(),
            vec![
                TransactionOutput::new(my_value, pk1),
                TransactionOutput::new(TransactionValue::new_id_transfer(data_hash)?, pk1),
            ],
        );

        let b0 = Block::new(
            BlockVersion::default(),
            *BlockHash::from_serialized(&t0.hash(), &mut 0)?,
            BlockHash::default(),
            Magic::new(0),
        );

        let mut b0_serialized = vec![0u8; Block::serialized_len()];
        b0.serialize_into(&mut b0_serialized, &mut 0)?;
        let mut miner = Miner::new_ranged(b0_serialized, 0..u64::MAX, [t0].to_vec());
        let mut wallet;
        match Wallet::mine_until_complete(&mut miner) {
            Some(b) => {
                let block_hash = b.hash();
                if !is_miner {
                    wallet = Wallet::default(pk1, sk1);
                } else {
                    wallet = Wallet::default_miner(pk1, sk1);
                }
                wallet.add_block(b)?;
                wallet.add_on_chain_transactions(miner.transactions, block_hash)?;
            }
            None => return Err(String::from("Could not mine first block")),
        };
        Ok(wallet)
    }

    pub fn mine_until_complete(miner: &mut Miner) -> Option<Block> {
        loop {
            match miner.do_work() {
                Poll::Ready(result) => return result,
                Poll::Pending => {}
            }
        }
    }

    pub fn generate_ec_keys() -> (PublicKey, SecretKey) {
        let secp = Secp256k1::new();
        let mut rng = rand::thread_rng();
        let (sk, pk) = secp.generate_keypair(&mut rng);
        (pk, sk)
    }
}
