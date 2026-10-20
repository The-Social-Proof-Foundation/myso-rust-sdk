// Copyright (c) The Social Proof Foundation, LLC.
// SPDX-License-Identifier: Apache-2.0

//! Sigma proofs matching `contra::nizk`.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use crate::elgamal::Ciphertext;
use crate::group::{self, g, h, mul, random_scalar};
use crate::nizk::fiat_shamir_challenge;

#[derive(Clone, Debug)]
pub struct DdhProof {
    pub a: RistrettoPoint,
    pub b: RistrettoPoint,
    pub z: Scalar,
}

impl DdhProof {
    pub fn prove(
        dst: &[u8],
        secret: &Scalar,
        base_g: &RistrettoPoint,
        base_h: &RistrettoPoint,
        x_g: &RistrettoPoint,
        x_h: &RistrettoPoint,
    ) -> Self {
        let nonce = random_scalar();
        let a = mul(base_g, &nonce);
        let b = mul(base_h, &nonce);
        let challenge = challenge_ddh(dst, base_g, base_h, x_g, x_h, &a, &b);
        Self {
            a,
            b,
            z: nonce + challenge * secret,
        }
    }

    pub fn verify(
        &self,
        dst: &[u8],
        base_g: &RistrettoPoint,
        base_h: &RistrettoPoint,
        x_g: &RistrettoPoint,
        x_h: &RistrettoPoint,
    ) -> bool {
        let challenge = challenge_ddh(dst, base_g, base_h, x_g, x_h, &self.a, &self.b);
        relation(&self.a, x_g, base_g, &self.z, &challenge)
            && relation(&self.b, x_h, base_h, &self.z, &challenge)
    }
}

fn challenge_ddh(
    dst: &[u8],
    base_g: &RistrettoPoint,
    base_h: &RistrettoPoint,
    x_g: &RistrettoPoint,
    x_h: &RistrettoPoint,
    a: &RistrettoPoint,
    b: &RistrettoPoint,
) -> Scalar {
    let owned = vec![
        dst.to_vec(),
        group::point_bytes(base_g).to_vec(),
        group::point_bytes(base_h).to_vec(),
        group::point_bytes(x_g).to_vec(),
        group::point_bytes(x_h).to_vec(),
        group::point_bytes(a).to_vec(),
        group::point_bytes(b).to_vec(),
    ];
    let refs: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
    fiat_shamir_challenge(&refs)
}

fn relation(
    commitment: &RistrettoPoint,
    known: &RistrettoPoint,
    base: &RistrettoPoint,
    response: &Scalar,
    challenge: &Scalar,
) -> bool {
    *commitment == mul(base, response) - mul(known, challenge)
}

#[derive(Clone, Debug)]
pub struct ElGamalProof {
    pub a: RistrettoPoint,
    pub b: RistrettoPoint,
    pub z1: Scalar,
    pub z2: Scalar,
}

impl ElGamalProof {
    pub fn prove(dst: &[u8], blinding: &Scalar, amount: u64, encryption: &Ciphertext, pk: &RistrettoPoint) -> Self {
        let r1 = random_scalar();
        let r2 = random_scalar();
        let a = mul(pk, &r1);
        let b = mul(&g(), &r1) + mul(&h(), &r2);
        let challenge = challenge_elgamal(dst, pk, encryption, &a, &b);
        Self {
            a,
            b,
            z1: r1 + challenge * blinding,
            z2: r2 + challenge * Scalar::from(amount),
        }
    }
}

fn challenge_elgamal(
    dst: &[u8],
    pk: &RistrettoPoint,
    encryption: &Ciphertext,
    a: &RistrettoPoint,
    b: &RistrettoPoint,
) -> Scalar {
    let owned = vec![
        dst.to_vec(),
        group::point_bytes(&g()).to_vec(),
        group::point_bytes(&h()).to_vec(),
        group::point_bytes(pk).to_vec(),
        group::point_bytes(&encryption.ciphertext).to_vec(),
        group::point_bytes(&encryption.decryption_handle).to_vec(),
        group::point_bytes(a).to_vec(),
        group::point_bytes(b).to_vec(),
    ];
    let refs: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
    fiat_shamir_challenge(&refs)
}

#[derive(Clone, Debug)]
pub struct MultiRecipient {
    pub commitment: RistrettoPoint,
    pub handles: Vec<RistrettoPoint>,
}

impl MultiRecipient {
    pub fn encrypt(keys: &[RistrettoPoint], value: u64, blinding: &Scalar) -> Self {
        Self {
            commitment: mul(&h(), &Scalar::from(value)) + mul(&g(), blinding),
            handles: keys.iter().map(|pk| mul(pk, blinding)).collect(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct KeyConsistencyProof {
    pub a1: Vec<RistrettoPoint>,
    pub a2: Vec<RistrettoPoint>,
    pub a3: RistrettoPoint,
    pub z1: Vec<Scalar>,
    pub z2: Vec<Scalar>,
}

pub fn scalar_to_u32_limbs(scalar: &Scalar) -> [u64; 8] {
    let bytes = scalar.to_bytes();
    let mut limbs = [0u64; 8];
    for (index, limb) in limbs.iter_mut().enumerate() {
        let start = index * 4;
        *limb = u64::from(u32::from_le_bytes(bytes[start..start + 4].try_into().unwrap()));
    }
    limbs
}

impl KeyConsistencyProof {
    pub fn prove(
        dst: &[u8],
        limbs: &[u64; 8],
        sender_pk: &RistrettoPoint,
        recipient_keys: &[RistrettoPoint],
        ciphertexts: &[MultiRecipient],
        blindings: &[Scalar; 8],
    ) -> Self {
        let masks_a: Vec<Scalar> = (0..8).map(|_| random_scalar()).collect();
        let masks_b: Vec<Scalar> = (0..8).map(|_| random_scalar()).collect();
        let mut a1 = Vec::new();
        for mask in &masks_a {
            for pk in recipient_keys {
                a1.push(mul(pk, mask));
            }
        }
        let a2: Vec<RistrettoPoint> = (0..8)
            .map(|index| mul(&g(), &masks_a[index]) + mul(&h(), &masks_b[index]))
            .collect();
        let mut shift = Scalar::ONE;
        let mut mask_sum = Scalar::ZERO;
        let step = Scalar::from(1u64 << 32);
        for mask in &masks_b {
            mask_sum += mask * shift;
            shift *= step;
        }
        let a3 = mul(&g(), &mask_sum);
        let challenge = challenge_key(dst, sender_pk, recipient_keys, ciphertexts, &a1, &a2, &a3);
        let z1 = (0..8)
            .map(|index| masks_a[index] + challenge * blindings[index])
            .collect();
        let z2 = (0..8)
            .map(|index| masks_b[index] + challenge * Scalar::from(limbs[index]))
            .collect();
        Self { a1, a2, a3, z1, z2 }
    }
}

fn challenge_key(
    dst: &[u8],
    sender_pk: &RistrettoPoint,
    recipient_keys: &[RistrettoPoint],
    ciphertexts: &[MultiRecipient],
    a1: &[RistrettoPoint],
    a2: &[RistrettoPoint],
    a3: &RistrettoPoint,
) -> Scalar {
    let mut owned = vec![
        dst.to_vec(),
        group::point_bytes(&g()).to_vec(),
        group::point_bytes(&h()).to_vec(),
        group::point_bytes(sender_pk).to_vec(),
    ];
    for key in recipient_keys {
        owned.push(group::point_bytes(key).to_vec());
    }
    for ciphertext in ciphertexts {
        owned.push(group::point_bytes(&ciphertext.commitment).to_vec());
        for handle in &ciphertext.handles {
            owned.push(group::point_bytes(handle).to_vec());
        }
    }
    for point in a1 {
        owned.push(group::point_bytes(point).to_vec());
    }
    for point in a2 {
        owned.push(group::point_bytes(point).to_vec());
    }
    owned.push(group::point_bytes(a3).to_vec());
    let refs: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
    fiat_shamir_challenge(&refs)
}

pub fn prove_is_zero(dst: &[u8], secret: &Scalar, pk: &RistrettoPoint, ciphertext: &Ciphertext) -> DdhProof {
    DdhProof::prove(dst, secret, &g(), &ciphertext.ciphertext, pk, &ciphertext.decryption_handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ddh_proof_verifies() {
        let secret = random_scalar();
        let base_h = h();
        let x_g = mul(&g(), &secret);
        let x_h = mul(&base_h, &secret);
        let proof = DdhProof::prove(b"dst", &secret, &g(), &base_h, &x_g, &x_h);
        assert!(proof.verify(b"dst", &g(), &base_h, &x_g, &x_h));
    }
}
