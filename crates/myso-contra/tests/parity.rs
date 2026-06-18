// Copyright (c) The Social Proof Foundation, LLC.
// SPDX-License-Identifier: Apache-2.0

//! Cross-SDK parity: Rust prover output matches `contra-crypto-fixtures` golden bytes
//! consumed by the TypeScript `@socialproof/contra` WASM verifier tests.

use myso_contra_crypto::{
    assert_wire_proof_valid, batch_range_proof_wire, fixtures::SINGLE_AMOUNT_RANGE_PROOF_HEX,
    SINGLE_AMOUNT_DST,
};
use rand::SeedableRng;
use rand::rngs::StdRng;

#[test]
fn rust_golden_proof_matches_ts_fixture_hex() {
    let mut rng = StdRng::seed_from_u64(42);
    let values = [1234u64, 0, 0, 0];
    let blindings = [7777u64, 0, 0, 0];
    let proof = batch_range_proof_wire(&values, &blindings, 16, SINGLE_AMOUNT_DST, &mut rng);
    assert_eq!(hex::encode(&proof), SINGLE_AMOUNT_RANGE_PROOF_HEX);
    assert_wire_proof_valid(&proof, &values, &blindings, 16, SINGLE_AMOUNT_DST);
}
