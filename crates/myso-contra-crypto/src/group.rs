// Copyright (c) The Social Proof Foundation, LLC.
// SPDX-License-Identifier: Apache-2.0

//! Ristretto255 points matching `contra::twisted_elgamal`.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;

pub use curve25519_dalek::ristretto::RistrettoPoint;
pub use curve25519_dalek::scalar::Scalar;
use rand::RngCore;
use rand::rngs::OsRng;

/// On-chain `h()`, `hash_to_curve("fastcrypto-blinding-gen-01")`.
pub const H_BYTES: [u8; 32] = [
    0x34, 0xce, 0x14, 0x77, 0xc1, 0x45, 0x58, 0x17, 0x80, 0x89, 0x50, 0x0a, 0x39, 0xc8, 0x64, 0xe0,
    0xf6, 0x07, 0xb3, 0xc1, 0xf4, 0x1a, 0xb3, 0x98, 0x40, 0x0e, 0x4a, 0x9d, 0xe6, 0xd2, 0xc4, 0x46,
];

pub fn g() -> RistrettoPoint {
    RISTRETTO_BASEPOINT_POINT
}

pub fn h() -> RistrettoPoint {
    CompressedRistretto(H_BYTES)
        .decompress()
        .expect("Contra H is a canonical ristretto point")
}

pub fn identity() -> RistrettoPoint {
    g() * Scalar::ZERO
}

pub fn point_from_bytes(bytes: &[u8]) -> Option<RistrettoPoint> {
    let bytes: [u8; 32] = bytes.try_into().ok()?;
    CompressedRistretto(bytes).decompress()
}

pub fn point_bytes(point: &RistrettoPoint) -> [u8; 32] {
    point.compress().to_bytes()
}

pub fn scalar_from_canonical(bytes: &[u8]) -> Option<Scalar> {
    let bytes: [u8; 32] = bytes.try_into().ok()?;
    Scalar::from_canonical_bytes(bytes).into()
}

pub fn scalar_bytes(scalar: &Scalar) -> [u8; 32] {
    scalar.to_bytes()
}

/// Uniform non-zero scalar. Proof randomness does not need to match the TypeScript sampler.
pub fn random_scalar() -> Scalar {
    loop {
        let mut wide = [0u8; 64];
        OsRng.fill_bytes(&mut wide);
        let scalar = Scalar::from_bytes_mod_order_wide(&wide);
        if scalar != Scalar::ZERO {
            return scalar;
        }
    }
}

pub fn mul(point: &RistrettoPoint, scalar: &Scalar) -> RistrettoPoint {
    point * scalar
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h_round_trips_to_the_move_constant() {
        assert_eq!(point_bytes(&h()), H_BYTES);
    }
}
