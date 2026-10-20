// Copyright (c) The Social Proof Foundation, LLC.
// SPDX-License-Identifier: Apache-2.0

uniffi::setup_scaffolding!();

#[derive(uniffi::Error, thiserror::Error, Debug)]
pub enum ContraBindError {
    #[error("{reason}")]
    Failed { reason: String },
}

#[derive(uniffi::Record)]
pub struct PrivateBalance {
    pub spendable: u64,
    pub pending: u64,
    pub pending_public: u64,
}

#[uniffi::export]
pub fn decrypt_private_balance(
    account_key: Vec<u8>,
    token_account_json: String,
) -> Result<PrivateBalance, ContraBindError> {
    let (spendable, pending, pending_public) =
        myso_contra::engine::decrypt_balance(&account_key, &token_account_json)
            .map_err(|error| ContraBindError::Failed { reason: error.to_string() })?;
    Ok(PrivateBalance {
        spendable,
        pending,
        pending_public,
    })
}

#[uniffi::export]
pub fn derived_token_account_id(
    package_id: String,
    account_registry_id: String,
    owner: String,
    token_type: String,
) -> Result<String, ContraBindError> {
    myso_contra::engine::token_account_object_id(&package_id, &account_registry_id, &owner, &token_type)
        .map_err(|error| ContraBindError::Failed { reason: error.to_string() })
}

#[uniffi::export]
pub fn account_public_key_hex(token_account_json: String) -> Result<String, ContraBindError> {
    myso_contra::engine::account_public_key_hex(&token_account_json)
        .map_err(|error| ContraBindError::Failed { reason: error.to_string() })
}

#[uniffi::export]
pub fn plan_private_transaction(request_json: String) -> Result<String, ContraBindError> {
    myso_contra::engine::plan_transaction(&request_json)
        .map_err(|error| ContraBindError::Failed { reason: error.to_string() })
}
