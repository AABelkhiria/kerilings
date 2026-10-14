// Anyone can build a rotation event. What makes one valid is that its new signing keys are the
// ones the previous establishment event committed to: the digest of each new key must appear in
// the previous event's next-key digests (`n`).
//
// This is the check that stops a thief who stole the current keys: they can sign a rotation to
// keys of their own, but those keys' digests were never committed to.

use keri_cesr::crypto::digest::{Digest, DigestAlgorithm};
use keri_cesr::crypto::verifier::VerificationKey;
use keri_protocol::event::KeyEvent;

/// Returns `true` when every key in `new_keys` was committed to by `previous`.
fn is_committed(previous: &KeyEvent, new_keys: &[VerificationKey]) -> bool {
    // TODO: Read the previous event's next-key digests and check that each new key's digest is
    // among them.
    todo!()
}

fn main() {
    // You can optionally experiment here.
}

#[cfg(test)]
mod tests {
    use super::*;
    use keri_cesr::crypto::signer::Signer;
    use keri_cesr::crypto::verifier::KeyTransferability;
    use keri_protocol::event::inception::InceptionBuilder;

    fn key(seed: u8) -> VerificationKey {
        Signer::from_seed(&[seed; 32], KeyTransferability::Transferable)
            .unwrap()
            .verifier()
            .clone()
    }

    fn inception() -> KeyEvent {
        let next = Digest::derive(
            DigestAlgorithm::Blake3_256,
            key(2).qb64().unwrap().as_bytes(),
        );
        InceptionBuilder::new(vec![key(1)])
            .next_key_digests(vec![next])
            .build()
            .unwrap()
    }

    #[test]
    fn the_committed_key_may_rotate_in() {
        assert!(is_committed(&inception(), &[key(2)]));
    }

    #[test]
    fn a_thief_cannot_rotate_to_their_own_key() {
        assert!(!is_committed(&inception(), &[key(66)]));
    }

    #[test]
    fn the_current_key_is_not_the_next_key() {
        assert!(!is_committed(&inception(), &[key(1)]));
    }
}
