// A digest is a fixed-size fingerprint of some bytes. KERI uses Blake3-256 (code `E`): any
// change to the input gives a completely different digest, and no one can find another input
// with the same digest.
//
// Digests are how KERI commits to data without including it: a self-addressing identifier is
// a digest, a seal anchoring a credential is a digest, a commitment to the next key is a digest.

use keri_cesr::crypto::digest::{Digest, DigestAlgorithm};

/// The Blake3-256 digest of `data`, in qb64.
fn fingerprint(data: &[u8]) -> String {
    Digest::derive(DigestAlgorithm::Blake3_256, data)
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
    fn known_digest() {
        assert_eq!(
            fingerprint(b"hello world"),
            "ENdJge-nCgyIC42MGYXQddvL9nm5ml-ZFOWq-WuDGp4k"
        );
    }

    #[test]
    fn any_change_shows() {
        assert_ne!(fingerprint(b"hello world"), fingerprint(b"hello world!"));
    }

    #[test]
    fn verifies_its_input() {
        let digest = Digest::from_qb64(&fingerprint(b"hello world")).unwrap();
        assert!(digest.verify(b"hello world"));
        assert!(!digest.verify(b"hello there"));
    }
}
