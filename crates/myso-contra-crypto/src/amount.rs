// Copyright (c) The Social Proof Foundation, LLC.
// SPDX-License-Identifier: Apache-2.0

//! Four-limb encrypted amounts.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use crate::elgamal::Ciphertext;
use crate::proofs::ElGamalProof;

#[derive(Clone, Copy, Debug)]
pub struct EncryptedAmount {
    pub limbs: [Ciphertext; 4],
}

impl EncryptedAmount {
    pub fn trivial(value: u64) -> Self {
        Self {
            limbs: split_u16(value).map(|limb| Ciphertext::trivial(limb)),
        }
    }

    pub fn collapse(self) -> Ciphertext {
        self.limbs[0].add(self.limbs[1].shift_left(16)).add(
            self.limbs[2]
                .shift_left(32)
                .add(self.limbs[3].shift_left(48)),
        )
    }

    pub fn decrypt(&self, secret_inverse: &Scalar) -> Result<u64, String> {
        let mut total = 0u64;
        for (index, limb) in self.limbs.iter().enumerate() {
            let plain = limb.decrypt_with_inverse(secret_inverse)?;
            total += plain << (16 * index);
        }
        Ok(total)
    }
}

pub fn split_u16(value: u64) -> [u64; 4] {
    [
        value & 0xffff,
        (value >> 16) & 0xffff,
        (value >> 32) & 0xffff,
        (value >> 48) & 0xffff,
    ]
}

#[derive(Clone, Debug)]
pub struct WellFormedLimb {
    pub value: u64,
    pub blinding: Scalar,
    pub ciphertext: Ciphertext,
    pub proof: ElGamalProof,
}

pub fn encrypt_limb(dst: &[u8], pk: &RistrettoPoint, value: u64) -> WellFormedLimb {
    let blinding = crate::group::random_scalar();
    let ciphertext = Ciphertext::encrypt(pk, value, &blinding);
    let proof = ElGamalProof::prove(dst, &blinding, value, &ciphertext, pk);
    WellFormedLimb {
        value,
        blinding,
        ciphertext,
        proof,
    }
}

pub fn encrypt_amount(dst: &[u8], pk: &RistrettoPoint, value: u64) -> [WellFormedLimb; 4] {
    split_u16(value).map(|limb| encrypt_limb(dst, pk, limb))
}

pub fn collapse_blindings(blindings: &[Scalar]) -> Scalar {
    let mut total = Scalar::ZERO;
    let mut place = Scalar::ONE;
    let step = Scalar::from(1u64 << 16);
    for blinding in blindings {
        total += blinding * place;
        place *= step;
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::{g, mul, random_scalar};

    #[test]
    fn four_limbs_reassemble() {
        let secret = random_scalar();
        let public = mul(&g(), &secret);
        let amount = encrypt_amount(b"dst", &public, 0x0001_0002_0003_0004);
        let encrypted = EncryptedAmount {
            limbs: [
                amount[0].ciphertext,
                amount[1].ciphertext,
                amount[2].ciphertext,
                amount[3].ciphertext,
            ],
        };
        assert_eq!(
            encrypted.decrypt(&secret.invert()).unwrap(),
            0x0001_0002_0003_0004
        );
    }
}
