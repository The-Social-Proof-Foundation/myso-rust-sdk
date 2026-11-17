// Copyright (c) The Social Proof Foundation, LLC.
// SPDX-License-Identifier: Apache-2.0

//! Proof generation primitives for the Contra confidential transfers protocol.

pub mod amount;
pub mod bulletproofs;
pub mod elgamal;
pub mod fixtures;
pub mod group;
pub mod nizk;
pub mod proofs;
pub mod types;
pub mod well_formed;

pub use bulletproofs::{
    assert_wire_proof_valid, batch_range_proof_wire, pedersen_commitment_bytes, range_from_bits,
};
pub use fixtures::{SINGLE_AMOUNT_DST, TWO_AMOUNT_DST, WRONG_DST};
pub use types::{PROTOCOL_DDH, PROTOCOL_ELGAMAL, PROTOCOL_KEY_CONSISTENCY, ProtocolId};
