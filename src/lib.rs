pub mod block;
pub mod block_hash;
pub mod block_version;
pub mod blockchain;
pub mod ec_key_serialization;
pub mod magic;
pub mod miner;
pub mod serialize;
pub mod transaction;
pub mod transaction_hash;
pub mod transaction_input;
pub mod transaction_output;
pub mod transaction_value;
pub mod transaction_varuint;
pub mod transaction_version;
pub mod wallet;

#[cfg(test)]
mod tests {
    use crate::{
        block_hash::BlockHash,
        ec_key_serialization::PUBLIC_KEY_COMPRESSED_SIZE,
        merkle_forest::HASH_SIZE,
        serialize::DynamicSized,
        transaction::{Transaction, SECP256K1_SIG_LEN},
        transaction_input::TransactionInput,
        transaction_output::TransactionOutput,
        transaction_value::TransactionValue,
        transaction_varuint::TransactionVarUint,
        wallet::{self, Wallet},
    };

    fn create_test_set() -> (Transaction, Wallet) {
        let (pk, sk) = crate::wallet::Wallet::generate_ec_keys();

        let mut wallet = Wallet::new(pk, sk, true).unwrap();
        let t0 = *wallet
            .mine_transaction(
                wallet::DEFAULT_N_THREADS,
                wallet::DEFAULT_PAR_WORK,
                crate::transaction::Transaction::new_coin_base_transaction(
                    [0u8; 64],
                    crate::transaction_output::TransactionOutput::new(
                        crate::transaction_value::TransactionValue::new_coin_transfer(100, 0)
                            .unwrap(),
                        pk,
                    ),
                ),
            )
            .unwrap();

        let t0_hash = t0.hash();
        wallet.add_off_chain_transaction(t0).unwrap();
        wallet
            .create_and_mine_block_from_off_chain_transactions()
            .unwrap();

        let tis = vec![crate::transaction_input::TransactionInput::new(
            wallet.get_head_hash(),
            t0_hash,
            TransactionVarUint::from(0),
        )];
        let tos = vec![crate::transaction_output::TransactionOutput::new(
            crate::transaction_value::TransactionValue::new_coin_transfer(100, 0).unwrap(),
            pk,
        )];
        (
            crate::transaction::Transaction::new(tis, tos).unwrap(),
            wallet,
        )
    }

    #[test]
    fn transaction_not_mined() {
        let (transaction, _) = create_test_set();
        assert!(!transaction.contains_enough_work());
    }

    #[test]
    fn transaction_serialized_len() {
        let (pk, sk) = crate::wallet::Wallet::generate_ec_keys();
        let mut transaction = Transaction::new(
            vec![TransactionInput::new(
                BlockHash::new_unworked().hash(),
                BlockHash::new_unworked().hash(),
                TransactionVarUint::from(0),
            )],
            vec![TransactionOutput::new(
                TransactionValue::new_coin_transfer(0, 0).unwrap(),
                pk,
            )],
        )
        .unwrap();
        transaction.sign(sk, 0).unwrap();
        let tver_len = 1;
        let tinput_len = 1 + HASH_SIZE * 2 + 1 + SECP256K1_SIG_LEN;
        let tout_len = 1 + 1 + 32 + PUBLIC_KEY_COMPRESSED_SIZE;
        let magic_len = 1;
        assert_eq!(
            transaction.serialized_len(),
            tver_len + tinput_len + tout_len + magic_len
        );
    }

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
    fn wallet_generation_and_mining_test() {
        match crate::wallet::Wallet::generate_init_blockchain(true) {
            Ok(wallet) => match wallet.to_binary() {
                Ok(bw) => {
                    println!("{:x?}", bw.blockchain_bin);
                    assert!(true)
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
        }
    }
}
