// Pre-rotation is KERI's answer to key compromise. When an identifier is created, it does not
// publish its next public key, only a digest of it: the digest of the key's qb64 text. The next
// key stays hidden until the rotation that uses it.
//
// An attacker who steals the current private key still cannot rotate: they would need a key
// whose digest matches the commitment, and they have never seen it.

use keri_cesr::crypto::digest::{Digest, DigestAlgorithm};
use keri_cesr::crypto::verifier::VerificationKey;

/// The commitment an event publishes for `next_key`.
fn commit(next_key: &VerificationKey) -> Digest {
    // TODO: Digest the next key's qb64 text, as bytes.
    todo!()
}

/// Whether `revealed` is the key that `commitment` committed to.
fn is_committed(commitment: &Digest, revealed: &VerificationKey) -> bool {
    commitment.verify(&revealed.qb64_bytes().unwrap())
}

fn main() {
    // You can optionally experiment here.
}

#[cfg(test)]
mod tests {
    use super::*;
    use keri_cesr::crypto::signer::Signer;
    use keri_cesr::crypto::verifier::KeyTransferability;

    fn key(seed: u8) -> VerificationKey {
        let signer = Signer::from_seed(&[seed; 32], KeyTransferability::Transferable).unwrap();
        signer.verifier().clone()
    }

    #[test]
    fn known_commitment() {
        let next = VerificationKey::from_qb64("DK4EmW6jcFeuJPADoXtA-BcgBoDMpkQaMA9Uywd4z6E2").unwrap();
        assert_eq!(
            commit(&next).qb64().unwrap(),
            "EIdCAErduP--zCFXfljIa1eRrW03rb80gxgWQjoQd7vI"
        );
    }

    #[test]
    fn rotation_reveals_the_committed_key() {
        let commitment = commit(&key(2));
        assert!(is_committed(&commitment, &key(2)));
    }

    #[test]
    fn an_attacker_key_does_not_match() {
        let commitment = commit(&key(2));
        assert!(!is_committed(&commitment, &key(66)));
    }
}
