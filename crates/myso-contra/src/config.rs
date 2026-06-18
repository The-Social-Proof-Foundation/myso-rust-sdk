// Copyright (c) The Social Proof Foundation, LLC.
// SPDX-License-Identifier: Apache-2.0

use myso_sdk_types::Address;

/// Published Contra package and shared registry object IDs.
#[derive(Clone, Debug)]
pub struct ContraPackageConfig {
    pub package_id: Address,
    pub account_registry_id: Address,
    pub token_registry_id: Address,
}

impl ContraPackageConfig {
    pub const DEFAULT_PACKAGE_ID: &str = "0xc1fe";

    pub fn new(
        package_id: Address,
        account_registry_id: Address,
        token_registry_id: Address,
    ) -> Self {
        Self {
            package_id,
            account_registry_id,
            token_registry_id,
        }
    }
}
