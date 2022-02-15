use crate::{
    serialize::{DynamicSized, Serialize},
    transaction_varuint::TransactionVarUint,
    wallet::HASH_SIZE,
};
use std::fmt::{self, Display, Formatter};

const TRANSACTION_FEE_LEN: usize = 16;
const TRANSACTION_VALUE_LEN: usize = 16;
pub const TRANSACTION_ID_LEN: usize = TRANSACTION_VALUE_LEN + TRANSACTION_FEE_LEN;

#[derive(Clone)]
pub struct TransactionValue {
    version: TransactionVarUint,
    value: [u8; TRANSACTION_ID_LEN],
}

impl TransactionValue {
    pub fn new_coin_transfer(value: u128, fee: u128) -> Result<Self, String> {
        let mut self_value = [0; TRANSACTION_VALUE_LEN + TRANSACTION_FEE_LEN];
        for (i, item) in self_value
            .iter_mut()
            .enumerate()
            .take(TRANSACTION_VALUE_LEN + TRANSACTION_FEE_LEN)
        {
            if i < TRANSACTION_VALUE_LEN {
                *item = (value >> ((TRANSACTION_VALUE_LEN - 1 - i) * 8)) as u8;
            } else {
                *item =
                    (fee >> (((TRANSACTION_VALUE_LEN + TRANSACTION_FEE_LEN) - 1 - i) * 8)) as u8;
            }
        }
        let tv = TransactionValue {
            version: TransactionVarUint::from(0),
            value: self_value,
        };
        if tv.is_coin_transfer() {
            Ok(tv)
        } else {
            Err(format!(
                "Sanity check failed, expected transaction value version {} got {}",
                0,
                tv.version.get_value()
            ))
        }
    }

    pub fn new_id_transfer(hash: [u8; HASH_SIZE]) -> Result<Self, String> {
        let mut value = [0; TRANSACTION_ID_LEN];
        value.copy_from_slice(&hash);
        let tv = TransactionValue {
            version: TransactionVarUint::from(1),
            value,
        };
        if tv.is_id_transfer() {
            Ok(tv)
        } else {
            Err(format!(
                "Sanity check failed, expected transaction value version {} got {}",
                0,
                tv.version.get_value()
            ))
        }
    }

    pub fn is_coin_transfer(&self) -> bool {
        self.version.get_value() == 0
    }

    pub fn is_id_transfer(&self) -> bool {
        self.version.get_value() == 1
    }

    pub fn get_value(&self) -> Result<u128, String> {
        if self.is_coin_transfer() {
            let mut value: u128 = 0;
            for (i, byte) in self.value[0..TRANSACTION_VALUE_LEN].iter().enumerate() {
                value += (*byte as u128) << ((TRANSACTION_VALUE_LEN - 1 - i) * 8);
            }
            Ok(value)
        } else {
            Err(String::from(
                "Cannot get transaction value: Transaction is not coin transfer",
            ))
        }
    }
    pub fn get_fee(&self) -> Result<u128, String> {
        if self.is_coin_transfer() {
            let mut fee: u128 = 0;
            for (i, byte) in self.value
                [TRANSACTION_VALUE_LEN..TRANSACTION_VALUE_LEN + TRANSACTION_FEE_LEN]
                .iter()
                .enumerate()
            {
                fee += (*byte as u128) << ((TRANSACTION_FEE_LEN - 1 - i) * 8);
            }
            Ok(fee)
        } else {
            Err(String::from(
                "Cannot get transaction value: Transaction is not coin transfer",
            ))
        }
    }
    pub fn get_id(&self) -> Result<[u8; TRANSACTION_ID_LEN], String> {
        if !self.is_coin_transfer() {
            Ok(self.value)
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
            write!(f, "{:?}ID", self.get_id().unwrap())
        }
    }
}

impl Serialize for TransactionValue {
    fn from_serialized(data: &[u8], i: &mut usize) -> Result<Box<TransactionValue>, String> {
        let version = *TransactionVarUint::from_serialized(data, i)?;
        let bytes_left = data.len() - *i;
        if bytes_left < TRANSACTION_VALUE_LEN + TRANSACTION_FEE_LEN {
            return Err(format!(
                "Too few bytes left to make transaction value, expected at least {} got {}",
                TRANSACTION_VALUE_LEN + TRANSACTION_FEE_LEN,
                bytes_left
            ));
        }
        let mut value = [0; TRANSACTION_VALUE_LEN + TRANSACTION_FEE_LEN];
        value.copy_from_slice(&data[*i..*i + TRANSACTION_VALUE_LEN + TRANSACTION_FEE_LEN]);
        *i += value.len();
        Ok(Box::new(TransactionValue { version, value }))
    }

    fn serialize_into(&self, data: &mut [u8], i: &mut usize) -> Result<(), String> {
        let bytes_left = data.len() - *i;
        if bytes_left < self.serialized_len() {
            return Err(format!(
                "Too few bytes left to serialize transaction value into, expected at least {} got {}",
                self.serialized_len(), bytes_left
            ));
        }
        self.version.serialize_into(data, i)?;
        data[*i..*i + TRANSACTION_VALUE_LEN + TRANSACTION_FEE_LEN].copy_from_slice(&self.value);
        *i += TRANSACTION_VALUE_LEN + TRANSACTION_FEE_LEN;
        Ok(())
    }
}

impl DynamicSized for TransactionValue {
    fn serialized_len(&self) -> usize {
        self.version.serialized_len() + TRANSACTION_VALUE_LEN + TRANSACTION_FEE_LEN
    }
}
