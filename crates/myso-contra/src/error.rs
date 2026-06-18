// Copyright (c) The Social Proof Foundation, LLC.
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ContraError {
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
}
