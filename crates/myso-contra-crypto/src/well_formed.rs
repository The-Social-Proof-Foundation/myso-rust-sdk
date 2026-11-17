// Copyright (c) The Social Proof Foundation, LLC.
// SPDX-License-Identifier: Apache-2.0

use curve25519_dalek::scalar::Scalar;

use crate::bulletproofs::{batch_range_proof_contra, batch_range_proof_wire};

/// Maximum encrypted amounts per Bulletproof chunk (matches `encrypted_amount.move`).
pub const MAX_BATCH_SIZE: usize = 8;

/// Canonical Bulletproof chunking for `n` amounts (matches TS `buildWellFormedProof`).
pub fn batch_sizes(n: usize) -> Vec<usize> {
    let mut sizes = Vec::new();
    let mut remaining = n;
    let mut chunk = MAX_BATCH_SIZE;
    while remaining > 0 {
        while remaining >= chunk {
            sizes.push(chunk);
            remaining -= chunk;
        }
        chunk /= 2;
    }
    sizes
}

/// Build DST-bound range proofs for a batch of limb `(value, blinding)` tuples.
pub fn build_well_formed_range_proofs(
    limbs: &[(u64, u64)],
    bit_size: u32,
    dst: &[u8],
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
) -> Vec<Vec<u8>> {
    let amounts = limbs.len() / 4;
    let sizes = batch_sizes(amounts);
    let mut proofs = Vec::new();
    let mut offset = 0;
    for chunk in sizes {
        let start = offset * 4;
        let end = start + chunk * 4;
        let chunk_limbs = &limbs[start..end];
        let values: Vec<u64> = chunk_limbs.iter().map(|(v, _)| *v).collect();
        let blindings: Vec<u64> = chunk_limbs.iter().map(|(_, b)| *b).collect();
        proofs.push(batch_range_proof_wire(
            &values, &blindings, bit_size, dst, rng,
        ));
        offset += chunk;
    }
    proofs
}

pub fn contra_range_proofs(limbs: &[(u64, Scalar)], bit_size: u32, dst: &[u8]) -> Vec<Vec<u8>> {
    build_contra_range_proofs(limbs, bit_size, dst, &mut rand::rngs::OsRng)
}

/// Contra-generator range proofs for full scalar blindings.
pub fn build_contra_range_proofs(
    limbs: &[(u64, Scalar)],
    bit_size: u32,
    dst: &[u8],
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
) -> Vec<Vec<u8>> {
    if limbs.is_empty() {
        return Vec::new();
    }
    let mut proofs = Vec::new();
    let mut offset = 0;
    let grouped = limbs.len() % 4 == 0;
    let chunk_count = if grouped {
        batch_sizes(limbs.len() / 4)
    } else {
        vec![limbs.len()]
    };
    for chunk in chunk_count {
        let start = if limbs.len() % 4 == 0 {
            offset * 4
        } else {
            offset
        };
        let width = if limbs.len() % 4 == 0 {
            chunk * 4
        } else {
            chunk
        };
        let slice = &limbs[start..start + width];
        let values: Vec<u64> = slice.iter().map(|(value, _)| *value).collect();
        let blindings: Vec<Scalar> = slice.iter().map(|(_, blinding)| *blinding).collect();
        proofs.push(batch_range_proof_contra(
            &values, &blindings, bit_size, dst, rng,
        ));
        offset += chunk;
    }
    proofs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_sizes_matches_move_examples() {
        assert_eq!(batch_sizes(7), vec![4, 2, 1]);
        assert_eq!(batch_sizes(8), vec![8]);
        assert_eq!(batch_sizes(20), vec![8, 8, 4]);
    }
}
