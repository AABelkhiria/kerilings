// CESR, the Composable Event Streaming Representation, encodes every piece of cryptographic
// material as text that starts with a derivation code. The code says what the material is;
// the rest is the material itself, in URL-safe Base64.
//
// `E` is the code for a 32-byte Blake3-256 digest, so 32 zero bytes encode as `E` followed by
// 43 `A`s.

use keri_cesr::code::DerivationCode;
use keri_cesr::matter::QualifiedMaterial;

/// The derivation code of a Blake3-256 digest.
fn blake3_digest_code() -> DerivationCode {
    DerivationCode::BLAKE3_256
}

fn main() {
    // You can optionally experiment here.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_digest() {
        let material =
            QualifiedMaterial::from_qb64("EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();

        assert!(material.code() == blake3_digest_code());
        assert_eq!(material.raw(), &[0_u8; 32]);
    }
}
