use crate::{
    serialize::{Serialize, StaticSized},
    user::User,
};
use secp256k1::PublicKey;
use std::{
    collections::HashMap,
    fmt::{self, Display, Formatter},
};

const TRANSACTION_TOTAL_LEN: usize = 16;
const TRANSACTION_ID_LEN: usize = TRANSACTION_TOTAL_LEN;
const TRANSACTION_FEE_LEN: usize = 8;
const TRANSACTION_VALUE_LEN: usize = TRANSACTION_TOTAL_LEN - TRANSACTION_FEE_LEN;

enum TransactionValueType {
    Coin,
    ID,
}

#[derive(Copy, Clone)]
pub struct TransactionValue {
    value: [u8; TRANSACTION_TOTAL_LEN],
}

impl TransactionValue {
    pub fn new_coin_transfer(value: u64, fee: u64) -> Result<Self, String> {
        let mut self_value = [0; TRANSACTION_TOTAL_LEN];
        for (i, byte) in self_value.iter().enumerate() {
            if i < TRANSACTION_FEE_LEN {
                self_value[i] = (fee >> ((TRANSACTION_FEE_LEN - 1 - i) * 8)) as u8;
            } else {
                self_value[i] =
                    (value >> (((TRANSACTION_VALUE_LEN + TRANSACTION_FEE_LEN) - 1 - i) * 8)) as u8;
            }
        }
        let tv = TransactionValue { value: self_value };
        if tv.is_coin_transfer() {
            Ok(tv)
        } else {
            Err("First bit in fee cannot be set (sign bit) for coin transfers".to_string())
        }
    }

    pub fn is_coin_transfer(&self) -> bool {
        self.value[0] & 0x80 == 0
    }

    pub fn get_value(&self) -> Result<u64, String> {
        if self.is_coin_transfer() {
            let mut value: u64 = 0;
            for (i, byte) in self.value
                [TRANSACTION_TOTAL_LEN - TRANSACTION_VALUE_LEN - 1..TRANSACTION_TOTAL_LEN]
                .iter()
                .enumerate()
            {
                value += (*byte as u64) << ((TRANSACTION_VALUE_LEN - 1 - i) * 8);
            }
            Ok(value)
        } else {
            Err(String::from(
                "Cannot get transaction value: Transaction is not coin transfer",
            ))
        }
    }
    pub fn get_fee(&self) -> Result<u64, String> {
        if self.is_coin_transfer() {
            let mut value: u64 = 0;
            for (i, byte) in self.value[0..TRANSACTION_FEE_LEN].iter().enumerate() {
                value += (*byte as u64) << ((TRANSACTION_FEE_LEN - 1 - i) * 8);
            }
            Ok(value)
        } else {
            Err(String::from(
                "Cannot get transaction value: Transaction is not coin transfer",
            ))
        }
    }
    pub fn get_id(self) -> Result<u128, String> {
        if !self.is_coin_transfer() {
            let mut value: u128 = 0;
            for (i, byte) in self.value[0..TRANSACTION_ID_LEN].iter().enumerate() {
                value += (*byte as u128) << ((TRANSACTION_ID_LEN - 1 - i) * 8);
            }
            Ok(value)
        } else {
            Err(String::from(
                "Cannot get transaction ID: Transaction not ID transfer",
            ))
        }
    }
}

impl Display for TransactionValue {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        if self.is_coin_transfer() {
            write!(
                f,
                "{}-{}CEL",
                self.get_value().unwrap(),
                self.get_fee().unwrap()
            )
        } else {
            write!(f, "{}ID", self.get_id().unwrap())
        }
    }
}

impl Serialize for TransactionValue {
    fn from_serialized(
        data: &[u8],
        i: &mut usize,
        _: &mut HashMap<PublicKey, User>,
    ) -> Result<Box<TransactionValue>, String> {
        let bytes_left = data.len() - *i;
        if bytes_left < TRANSACTION_TOTAL_LEN {
            return Err(format!(
                "Too few bytes left to make transaction value, expected at least {} got {}",
                TRANSACTION_TOTAL_LEN, bytes_left
            ));
        }
        let mut value = [0; TRANSACTION_TOTAL_LEN];
        value.copy_from_slice(&data[*i..*i + TRANSACTION_TOTAL_LEN]);
        Ok(Box::new(TransactionValue { value }))
    }
    fn serialize_into(&self, data: &mut [u8], i: &mut usize) -> Result<usize, String> {
        let bytes_left = data.len() - *i;
        if bytes_left < TRANSACTION_TOTAL_LEN {
            return Err(format!(
                "Too few bytes left to serialize transaction value into, expected at least {} got {}",
                TRANSACTION_TOTAL_LEN, bytes_left
            ));
        }
        data[*i..*i + TRANSACTION_TOTAL_LEN].copy_from_slice(&self.value);
        *i += TRANSACTION_TOTAL_LEN;
        Ok(TRANSACTION_TOTAL_LEN)
    }
}

impl StaticSized for TransactionValue {
    fn serialized_len() -> usize {
        TRANSACTION_TOTAL_LEN
    }
}
