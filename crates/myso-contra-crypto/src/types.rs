// Copyright (c) The Social Proof Foundation, LLC.
// SPDX-License-Identifier: Apache-2.0

pub const PROTOCOL_DDH: u8 = 0x01;
pub const PROTOCOL_ELGAMAL: u8 = 0x02;
pub const PROTOCOL_KEY_CONSISTENCY: u8 = 0x03;
pub const PROTOCOL_VERIFIED_DEC: u8 = 100;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolId {
    Ddh,
    ElGamal,
    KeyConsistency,
    VerifiedDec,
}

impl ProtocolId {
    pub fn as_byte(self) -> u8 {
        match self {
            Self::Ddh => PROTOCOL_DDH,
            Self::ElGamal => PROTOCOL_ELGAMAL,
            Self::KeyConsistency => PROTOCOL_KEY_CONSISTENCY,
            Self::VerifiedDec => PROTOCOL_VERIFIED_DEC,
        }
    }
}

/// 21-byte Fiat-Shamir DST: `session_id || protocol_id`.
pub fn dst(session_id: &[u8; 20], protocol_id: u8) -> [u8; 21] {
    let mut out = [0u8; 21];
    out[..20].copy_from_slice(session_id);
    out[20] = protocol_id;
    out
}
