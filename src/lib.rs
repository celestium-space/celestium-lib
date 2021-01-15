pub mod block;
pub mod block_hash;
pub mod block_version;
pub mod blockchain;
pub mod ec_key_serialization;
pub mod merkle_forest;
pub mod miner;
pub mod serialize;
pub mod transaction;
pub mod transaction_input;
pub mod transaction_output;
pub mod transaction_value;
pub mod transaction_varuint;
pub mod transaction_version;
pub mod wallet;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert!(
            match crate::wallet::Wallet::generate_init_blockchain(true) {
                Ok(_) => {
                    println!("All good!");
                    true
                }
                Err(e) => {
                    println!("{}", e);
                    false
                }
            },
        )
    }
}
