// Copyright (c) The Social Proof Foundation, LLC.
// SPDX-License-Identifier: Apache-2.0

use myso_sdk_types::{Address, StructTag, TypeTag};
use myso_transaction_builder::{Argument, Function, ObjectInput, TransactionBuilder};
use std::str::FromStr;

use crate::config::ContraPackageConfig;
use crate::error::ContraError;

/// Builds programmable transactions for [`0xc1fe::contra`](https://github.com/The-Social-Proof-Foundation/myso-core).
pub struct ContraClient {
    config: ContraPackageConfig,
}

impl ContraClient {
    pub fn new(config: ContraPackageConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &ContraPackageConfig {
        &self.config
    }

    fn contra_fn(&self, module: &str, function: &str) -> Function {
        Function::new(
            self.config.package_id,
            module.parse().unwrap(),
            function.parse().unwrap(),
        )
    }

    fn type_arg(&self, token_type: &StructTag) -> TypeTag {
        TypeTag::Struct(Box::new(token_type.clone()))
    }

    /// `contra::new_account` — create a shared account for `owner`.
    pub fn new_account(&self, builder: &mut TransactionBuilder, owner: Address) -> Argument {
        let owner = builder.pure(&owner);
        builder.move_call(self.contra_fn("contra", "new_account"), vec![owner])
    }

    /// `contra::register` — register a token account with optional auditor key encryption.
    pub fn register(
        &self,
        builder: &mut TransactionBuilder,
        token_type: &StructTag,
        auth: Argument,
        public_key: Argument,
        key_encryption: Option<Argument>,
    ) -> Argument {
        let key_encryption =
            key_encryption.unwrap_or_else(|| builder.pure(&None::<Vec<u8>>));
        builder.move_call(
            self.contra_fn("contra", "register").with_type_args(vec![self.type_arg(token_type)]),
            vec![auth, public_key, key_encryption],
        )
    }

    /// `contra::wrap` — deposit public coins into pending encrypted balance.
    pub fn wrap(
        &self,
        builder: &mut TransactionBuilder,
        token_type: &StructTag,
        auth: Argument,
        confidential_token: Argument,
        coin: Argument,
        receiver: Address,
        memo: Option<Vec<u8>>,
    ) -> Argument {
        let receiver = builder.pure(&receiver);
        let memo = builder.pure(&memo.unwrap_or_default());
        builder.move_call(
            self.contra_fn("contra", "wrap").with_type_args(vec![self.type_arg(token_type)]),
            vec![auth, confidential_token, coin, receiver, memo],
        )
    }

    /// `contra::batched_transfer` — start a confidential transfer batch.
    pub fn batched_transfer(
        &self,
        builder: &mut TransactionBuilder,
        token_type: &StructTag,
        sender: Argument,
        auth: Argument,
        confidential_token: Argument,
        receiver_pks: Argument,
        receiver_amounts: Argument,
        well_formed_proofs: Argument,
        sender_amounts: Argument,
        consistency_proof: Argument,
        new_balance: Argument,
        balance_proof: Argument,
    ) -> Argument {
        builder.move_call(
            self.contra_fn("contra", "batched_transfer")
                .with_type_args(vec![self.type_arg(token_type)]),
            vec![
                sender,
                auth,
                confidential_token,
                receiver_pks,
                receiver_amounts,
                well_formed_proofs,
                sender_amounts,
                consistency_proof,
                new_balance,
                balance_proof,
            ],
        )
    }

    /// `contra::add_to_batch` — credit the next receiver in a batch.
    pub fn add_to_batch(
        &self,
        builder: &mut TransactionBuilder,
        token_type: &StructTag,
        batch: Argument,
        receiver: Address,
        memo: Vec<u8>,
    ) -> Argument {
        let receiver = builder.pure(&receiver);
        let memo = builder.pure(&memo);
        builder.move_call(
            self.contra_fn("contra", "add_to_batch").with_type_args(vec![self.type_arg(token_type)]),
            vec![batch, receiver, memo],
        )
    }

    /// `contra::try_finalize` — finalize a transfer batch.
    pub fn try_finalize(
        &self,
        builder: &mut TransactionBuilder,
        token_type: &StructTag,
        batch: Argument,
    ) -> Argument {
        builder.move_call(
            self.contra_fn("contra", "try_finalize").with_type_args(vec![self.type_arg(token_type)]),
            vec![batch],
        )
    }

    /// `contra::try_unwrap` — unwrap confidential balance to public coins.
    pub fn unwrap(
        &self,
        builder: &mut TransactionBuilder,
        token_type: &StructTag,
        account: Argument,
        auth: Argument,
        confidential_token: Argument,
        pool: Argument,
        new_balance: Argument,
        new_balance_proof: Argument,
        amount: u64,
        balance_proof: Argument,
    ) -> Argument {
        let amount = builder.pure(&amount);
        builder.move_call(
            self.contra_fn("contra", "try_unwrap").with_type_args(vec![self.type_arg(token_type)]),
            vec![
                account,
                auth,
                confidential_token,
                pool,
                new_balance,
                new_balance_proof,
                amount,
                balance_proof,
            ],
        )
    }

    /// `contra::authorize_as_sender` — permissionless auth for sender operations.
    pub fn authorize_as_sender(
        &self,
        builder: &mut TransactionBuilder,
        token_type: &StructTag,
    ) -> Argument {
        builder.move_call(
            self.contra_fn("contra", "authorize_as_sender")
                .with_type_args(vec![self.type_arg(token_type)]),
            vec![],
        )
    }

    /// Derive the shared account object ID for `owner`.
    pub fn account_id(&self, owner: Address) -> Result<Address, ContraError> {
        let key_type = format!("{}::contra::AccountKey", self.config.package_id.to_hex());
        let key_type_tag = TypeTag::from_str(&key_type).map_err(|_| {
            ContraError::InvalidArgument(format!("invalid account key type {key_type}"))
        })?;
        Ok(self.config.account_registry_id.derive_object_id(
            &key_type_tag,
            &bcs::to_bytes(&owner).expect("address is BCS-serializable"),
        ))
    }

    /// Shared object input for the confidential token registry entry.
    pub fn confidential_token_input(&self, object_id: Address, initial_version: u64) -> ObjectInput {
        ObjectInput::shared(object_id, initial_version, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_register_move_call() {
        let package: Address = ContraPackageConfig::DEFAULT_PACKAGE_ID.parse().unwrap();
        let config = ContraPackageConfig::new(
            package,
            "0x10".parse().unwrap(),
            "0x11".parse().unwrap(),
        );
        let client = ContraClient::new(config);
        let token_type = StructTag::from_str("0x2::myso::MYSO").unwrap();
        let mut builder = TransactionBuilder::new();
        let auth = client.authorize_as_sender(&mut builder, &token_type);
        let pk = builder.pure(&vec![0u8; 32]);
        let _account = client.register(&mut builder, &token_type, auth, pk, None);
    }
}
