// A `QualifiedMaterial` is raw bytes plus the derivation code that qualifies them. Encoding it
// gives the qb64 text you see everywhere in KERI: keys, digests and signatures are all qb64.
//
// Decoding goes the other way: the code says how much to read, and the raw bytes come back
// unchanged.

use keri_cesr::code::DerivationCode;
use keri_cesr::matter::QualifiedMaterial;

/// Encodes 32 raw bytes as a transferable Ed25519 public key.
fn encode_key(raw: &[u8]) -> String {
    QualifiedMaterial::new(DerivationCode::ED25519, raw)
        .unwrap()
        .qb64()
        .unwrap()
}

fn main() {
    // You can optionally experiment here.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_with_the_code_first() {
        let raw: Vec<u8> = (1..=32).collect();
        assert_eq!(
            encode_key(&raw),
            "DAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g"
        );
    }

    #[test]
    fn round_trips() {
        let raw = [42_u8; 32];
        let decoded = QualifiedMaterial::from_qb64(&encode_key(&raw)).unwrap();
        assert!(decoded.code() == DerivationCode::ED25519);
        assert_eq!(decoded.raw(), &raw);
    }
}
