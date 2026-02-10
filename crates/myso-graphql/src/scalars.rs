//! GraphQL scalar types for MySocial.

use std::borrow::Cow;

use serde::Deserialize;

/// `SuiAddress` scalar in MySo GraphQL schema. 32-byte hex-encoded address with `0x` prefix.
pub use myso_sdk_types::Address;

/// Useful for digest fields (Base58 string). Not a scalar in MySo GraphQL schema.
pub use myso_sdk_types::Digest;

/// `BigInt` scalar in MySo GraphQL schema.
///
/// Represented as a string because JSON numbers cannot reliably represent 64-bit integers.
/// Deserializes from a string and parses as u64.
pub struct BigInt(pub u64);

impl<'de> Deserialize<'de> for BigInt {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = <Cow<'_, str>>::deserialize(deserializer)?;
        let value = s.parse().map_err(serde::de::Error::custom)?;
        Ok(BigInt(value))
    }
}
