// Copyright (c) The Social Proof Foundation, LLC.
// SPDX-License-Identifier: Apache-2.0

//! Twisted ElGamal and a 16-bit baby-step giant-step table.

use std::collections::HashMap;
use std::sync::OnceLock;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use crate::group::{self, g, h, identity, mul};

pub const TABLE_BITS: u32 = 16;
const TABLE_SIZE: u64 = 1 << TABLE_BITS;

#[derive(Clone, Copy, Debug)]
pub struct Ciphertext {
    pub ciphertext: RistrettoPoint,
    pub decryption_handle: RistrettoPoint,
}

impl Ciphertext {
    pub fn encrypt(pk: &RistrettoPoint, value: u64, blinding: &Scalar) -> Self {
        Self {
            ciphertext: mul(&h(), &Scalar::from(value)) + mul(&g(), blinding),
            decryption_handle: mul(pk, blinding),
        }
    }

    pub fn trivial(value: u64) -> Self {
        Self {
            ciphertext: mul(&h(), &Scalar::from(value)),
            decryption_handle: identity(),
        }
    }

    pub fn add(self, other: Self) -> Self {
        Self {
            ciphertext: self.ciphertext + other.ciphertext,
            decryption_handle: self.decryption_handle + other.decryption_handle,
        }
    }

    pub fn subtract(self, other: Self) -> Self {
        Self {
            ciphertext: self.ciphertext - other.ciphertext,
            decryption_handle: self.decryption_handle - other.decryption_handle,
        }
    }

    pub fn shift_left(self, bits: u32) -> Self {
        let factor = Scalar::from(1u64 << bits);
        Self {
            ciphertext: mul(&self.ciphertext, &factor),
            decryption_handle: mul(&self.decryption_handle, &factor),
        }
    }

    pub fn decrypt(&self, secret: &Scalar) -> Result<u64, String> {
        let inverse = secret.invert();
        self.decrypt_with_inverse(&inverse)
    }

    pub fn decrypt_with_inverse(&self, secret_inverse: &Scalar) -> Result<u64, String> {
        let table = discrete_log_table();
        let mut point = self.ciphertext - mul(&self.decryption_handle, secret_inverse);
        let mut giant = 0u64;
        while giant < TABLE_SIZE {
            if let Some(baby) = table.lookup(&point) {
                return Ok(giant * TABLE_SIZE + u64::from(baby));
            }
            point -= table.giant_step;
            giant += 1;
        }
        Err("ciphertext is outside the discrete-log table".to_owned())
    }
}

struct DiscreteLogTable {
    entries: HashMap<[u8; 32], u32>,
    giant_step: RistrettoPoint,
}

impl DiscreteLogTable {
    fn lookup(&self, point: &RistrettoPoint) -> Option<u32> {
        self.entries.get(&group::point_bytes(point)).copied()
    }
}

fn discrete_log_table() -> &'static DiscreteLogTable {
    static TABLE: OnceLock<DiscreteLogTable> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut entries = HashMap::with_capacity(TABLE_SIZE as usize);
        let step = h();
        let mut point = identity();
        for index in 0..TABLE_SIZE as u32 {
            entries.insert(group::point_bytes(&point), index);
            point += step;
        }
        DiscreteLogTable {
            entries,
            giant_step: mul(&h(), &Scalar::from(TABLE_SIZE)),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::random_scalar;

    #[test]
    fn decrypts_a_u16_limb() {
        let secret = random_scalar();
        let public = mul(&g(), &secret);
        let blinding = random_scalar();
        let ciphertext = Ciphertext::encrypt(&public, 42_001, &blinding);
        assert_eq!(ciphertext.decrypt(&secret).unwrap(), 42_001);
    }
}
