// A signature binds a key to the exact bytes it signed. Change one byte of the message, one bit
// of the signature, or use another key, and verification fails.
//
// This is what makes KERI events tamper-evident: a verifier recomputes nothing on trust, it only
// checks signatures against the keys the event log says were authoritative.

use keri_cesr::crypto::verifier::VerificationKey;

/// Whether `signature` is a valid signature by `key` over `message`.
fn is_authentic(key: &VerificationKey, signature: &[u8], message: &[u8]) -> bool {
    key.verify(signature, message).is_ok()
}

fn main() {
    // You can optionally experiment here.
}

#[cfg(test)]
mod tests {
    use super::*;
    use keri_cesr::crypto::signer::Signer;
    use keri_cesr::crypto::verifier::KeyTransferability;

    fn signer(seed: u8) -> Signer {
        Signer::from_seed(&[seed; 32], KeyTransferability::Transferable).unwrap()
    }

    #[test]
    fn genuine() {
        let signer = signer(7);
        let signature = signer.sign_unindexed(b"pay Alice 10").unwrap();
        assert!(is_authentic(
            signer.verifier(),
            signature.raw(),
            b"pay Alice 10"
        ));
    }

    #[test]
    fn tampered_message() {
        let signer = signer(7);
        let signature = signer.sign_unindexed(b"pay Alice 10").unwrap();
        assert!(!is_authentic(
            signer.verifier(),
            signature.raw(),
            b"pay Alice 99"
        ));
    }

    #[test]
    fn tampered_signature() {
        let signer = signer(7);
        let mut signature = signer
            .sign_unindexed(b"pay Alice 10")
            .unwrap()
            .raw()
            .to_vec();
        signature[0] ^= 1;
        assert!(!is_authentic(
            signer.verifier(),
            &signature,
            b"pay Alice 10"
        ));
    }

    #[test]
    fn another_key() {
        let signature = signer(7).sign_unindexed(b"pay Alice 10").unwrap();
        assert!(!is_authentic(
            signer(8).verifier(),
            signature.raw(),
            b"pay Alice 10"
        ));
    }
}
