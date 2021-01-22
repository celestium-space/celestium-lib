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
    fn var_uint_from_usize() {
        let var_uint = crate::transaction_varuint::TransactionVarUint::from(0x12345678);
        assert_eq!(
            var_uint.value,
            [0b10000001, 0b10010001, 0b11010001, 0b10101100, 0b01111000]
        );
        assert_eq!(var_uint.get_value(), 0x12345678);
    }

    #[test]
    fn magic_increase1() {
        let mut var_uint = crate::transaction_varuint::TransactionVarUint::from(0x12345678);
        let len = var_uint.value.len();
        crate::magic::Magic::increase(&mut var_uint.value, len);
        assert_eq!(var_uint.get_value(), 0x12345679)
    }

    #[test]
    fn magic_increase2() {
        let mut var_uint = crate::transaction_varuint::TransactionVarUint::from(0xff00ff);
        let len = var_uint.value.len();
        crate::magic::Magic::increase(&mut var_uint.value, len);
        assert_eq!(var_uint.get_value(), 0xff0100)
    }

    #[test]
    fn magic_increase3() {
        let mut var_uint = crate::transaction_varuint::TransactionVarUint::from(0xffffff);
        let len = var_uint.value.len();
        crate::magic::Magic::increase(&mut var_uint.value, len);
        assert_eq!(var_uint.get_value(), 0x1000000)
    }

    #[test]
    fn magic_increase4() {
        let mut var_uint = crate::transaction_varuint::TransactionVarUint::from(0);
        let len = var_uint.value.len();
        crate::magic::Magic::increase(&mut var_uint.value, len);
        assert_eq!(var_uint.get_value(), 0x1)
    }

    #[test]
    fn magic_len_test() {
        let var_uint = crate::transaction_varuint::TransactionVarUint::from(
            crate::wallet::DEFAULT_PAR_WORK as usize,
        );
        let test_len = var_uint.value.len();
        for i in 1..crate::wallet::DEFAULT_N_THREADS {
            let var_uint = crate::transaction_varuint::TransactionVarUint::from(
                (i * crate::wallet::DEFAULT_PAR_WORK) as usize,
            );
            println!("{}: {:x?}", i, var_uint.value);
            assert_eq!(var_uint.value.len(), test_len)
        }
        let var_uint = crate::transaction_varuint::TransactionVarUint::from(
            ((crate::wallet::DEFAULT_N_THREADS + 1) * crate::wallet::DEFAULT_PAR_WORK) as usize,
        );
        println!("l: {:x?}", var_uint.value);
        assert_eq!(var_uint.value.len(), test_len + 1)
    }

    // #[test]
    // fn wallet_generation_and_mining_test() {
    //     let (pk2, _) = crate::wallet::Wallet::generate_ec_keys();
    //     match crate::wallet::Wallet::generate_init_blockchain(true) {
    //         Ok(mut wallet) => {
    //             match crate::transaction_value::TransactionValue::new_coin_transfer(500, 10) {
    //                 Ok(value) => match wallet.send(pk2, value) {
    //                     Ok(_) => match wallet.miner_from_off_chain_transactions(0, u64::MAX) {
    //                         Ok(mut miner) => {
    //                             let now = std::time::Instant::now();
    //                             while miner.do_work().is_pending() {}
    //                             match miner.do_work() {
    //                                 std::task::Poll::Ready(_) => {
    //                                     println!("Mining time: {}ms", now.elapsed().as_millis());
    //                                     assert!(true)
    //                                 }
    //                                 std::task::Poll::Pending => {
    //                                     println!("Mining error; Got pending after done");
    //                                     assert!(false)
    //                                 }
    //                             }
    //                         }
    //                         Err(e) => {
    //                             println!("{}", e);
    //                             assert!(false)
    //                         }
    //                     },
    //                     Err(e) => {
    //                         println!("{}", e);
    //                         assert!(false)
    //                     }
    //                 },
    //                 Err(e) => {
    //                     println!("{}", e);
    //                     assert!(false)
    //                 }
    //             }
    //         }
    //         Err(e) => {
    //             println!("{}", e);
    //             assert!(false)
    //         }
    //     }
    // }
}
