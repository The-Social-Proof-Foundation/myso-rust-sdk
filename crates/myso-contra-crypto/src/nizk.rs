// Copyright (c) The Social Proof Foundation, LLC.
// SPDX-License-Identifier: Apache-2.0

use blake2::digest::{consts::U32, Digest};
use blake2::Blake2b;
use curve25519_dalek::scalar::Scalar;

type Blake2b256 = Blake2b<U32>;

/// Fiat-Shamir challenge matching `contra::nizk::fiat_shamir_challenge`:
/// BCS `vector<vector<u8>>` + Blake2b-256, top byte zeroed.
pub fn fiat_shamir_challenge(parts: &[&[u8]]) -> Scalar {
    let serialized = bcs::to_bytes(
        &parts
            .iter()
            .map(|p| p.to_vec())
            .collect::<Vec<Vec<u8>>>(),
    )
    .expect("fiat-shamir transcript must be BCS-serializable");
    let hash = Blake2b256::digest(&serialized);
    let mut bytes = <[u8; 32]>::from(hash);
    bytes[31] = 0;
    Scalar::from_bytes_mod_order(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_is_deterministic() {
        let a = fiat_shamir_challenge(&[b"dst", b"point"]);
        let b = fiat_shamir_challenge(&[b"dst", b"point"]);
        assert_eq!(a, b);
    }
}
