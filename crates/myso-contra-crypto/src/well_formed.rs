// Copyright (c) The Social Proof Foundation, LLC.
// SPDX-License-Identifier: Apache-2.0

use crate::bulletproofs::batch_range_proof_wire;

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
