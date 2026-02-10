// Copyright (c) Mysten Labs, Inc.
// Copyright (c) The Social Proof Foundation, LLC.
// SPDX-License-Identifier: Apache-2.0

use myso_sdk_types::Address;

#[derive(thiserror::Error, Debug, Clone)]
#[non_exhaustive]
pub enum Error {
    #[error("Conversion error due to input issue: {0}")]
    Input(String),
    #[error("Gas object should be an immutable or owned object")]
    WrongGasObject,
    #[error("Missing object id")]
    MissingObjectId,
    #[error("Missing version for object {0}")]
    MissingVersion(Address),
    #[error("Missing digest for object {0}")]
    MissingDigest(Address),
    #[error("Missing sender")]
    MissingSender,
    #[error("Missing gas objects")]
    MissingGasObjects,
    #[error("Missing gas budget")]
    MissingGasBudget,
    #[error("Missing gas price")]
    MissingGasPrice,
    #[error("Missing object kind for object {0}")]
    MissingObjectKind(Address),
    #[error("Unknown shared object mutability for object {0}")]
    SharedObjectMutability(Address),
}
