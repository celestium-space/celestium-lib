use crate::{transaction::TransactionValue, universal_id::UniversalId};
use secp256k1::PublicKey;
use std::fmt;

pub struct User {
    pk: PublicKey,
    current_uid: UniversalId,
    current_balance: u32,
    ids: Vec<u32>,
}

impl User {
    pub fn new(pk: PublicKey) -> User {
        User {
            pk,
            current_uid: UniversalId::new(false, false, 0),
            current_balance: 0,
            ids: Vec::new(),
        }
    }

    pub fn get_balance(&self) -> u32 {
        self.current_balance
    }

    pub fn get_uid(&self) -> UniversalId {
        self.current_uid
    }

    pub fn give(&mut self, value: TransactionValue) -> Result<bool, String> {
        if value.is_coin_transfer()? {
            self.current_balance += value.get_value()?;
        } else {
            let tmp_id = value.get_id()?;
            if !self.ids.contains(&tmp_id) {
                self.ids.push(tmp_id);
            } else {
                return Err(format!(
                    "Trying to give user with pk {:?} the ID {}, which they already own",
                    self.pk, tmp_id
                ));
            }
        }
        Ok(true)
    }
    pub fn take(&mut self, value: TransactionValue) -> Result<bool, String> {
        if value.is_coin_transfer()? {
            let tmp_value = value.get_value()?;
            if tmp_value <= self.current_balance {
                self.current_balance -= tmp_value;
            } else {
                return Err(format!("Trying to take {} from user with pk {:?}. This would make their balance negative ({})", tmp_value, self.pk, self.current_balance as i32 - tmp_value as i32));
            }
        } else {
            let tmp_id = value.get_id()?;
            if self.ids.contains(&tmp_id) {
                self.ids.push(tmp_id);
            } else {
                return Err(format!(
                    "Trying to take unowned id {} from user with pk {:?}",
                    tmp_id, self.pk,
                ));
            }
        }
        self.current_uid.increment();
        Ok(true)
    }
}

impl fmt::Display for User {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "UPK:{:?}", self.pk)
    }
}
