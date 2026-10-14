// CESR has two domains for the same primitive: text (qb64) and binary (qb2). qb2 is the qb64
// text decoded from Base64, so every 4 characters become 3 bytes. A stream can switch between
// the two and back without losing anything; that is the "composable" in CESR.
//
// The binary form is a quarter shorter, which matters for constrained devices and storage.

use keri_cesr::matter::QualifiedMaterial;

const KEY: &str = "DAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g";

/// The binary (qb2) form of `material`.
fn to_binary(material: &QualifiedMaterial) -> Vec<u8> {
    material.qb2().unwrap()
}

fn main() {
    // You can optionally experiment here.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_is_three_quarters_of_text() {
        let key = QualifiedMaterial::from_qb64(KEY).unwrap();
        let binary = to_binary(&key);
        assert_eq!(binary.len(), KEY.len() / 4 * 3);
    }

    #[test]
    fn both_domains_hold_the_same_material() {
        let key = QualifiedMaterial::from_qb64(KEY).unwrap();
        let from_binary = QualifiedMaterial::from_qb2(&to_binary(&key)).unwrap();
        assert_eq!(from_binary.qb64().unwrap(), KEY);
    }
}
