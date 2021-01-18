pub mod block;
pub mod block_hash;
pub mod block_version;
pub mod blockchain;
pub mod ec_key_serialization;
pub mod magic;
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
    fn single_core_mining_speed() {
        let (pk2, _) = crate::wallet::Wallet::generate_ec_keys();
        match crate::wallet::Wallet::generate_init_blockchain(true) {
            Ok(mut wallet) => {
                match crate::transaction_value::TransactionValue::new_coin_transfer(500, 10) {
                    Ok(value) => match wallet.send(pk2, value) {
                        Ok(_) => match wallet.miner_from_off_chain_transactions(0, u64::MAX) {
                            Ok(mut miner) => {
                                let now = std::time::Instant::now();
                                while miner.do_work().is_pending() {}
                                match miner.do_work() {
                                    std::task::Poll::Ready(_) => {
                                        println!("Mining time: {}ms", now.elapsed().as_millis());
                                        assert!(true)
                                    }
                                    std::task::Poll::Pending => {
                                        println!("Mining error; Got pending after done");
                                        assert!(false)
                                    }
                                }
                            }
                            Err(e) => {
                                println!("{}", e);
                                assert!(false)
                            }
                        },
                        Err(e) => {
                            println!("{}", e);
                            assert!(false)
                        }
                    },
                    Err(e) => {
                        println!("{}", e);
                        assert!(false)
                    }
                }
            }
            Err(e) => {
                println!("{}", e);
                assert!(false)
            }
        }
    }
}
