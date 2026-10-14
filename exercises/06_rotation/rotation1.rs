// A rotation event (`rot`) replaces an identifier's signing keys with the ones its previous
// establishment event committed to, and commits to a new set of next keys in turn.
//
// Every event after inception is chained to the one before it:
//
// - `s`: its sequence number, one more than the previous event's. Inception is 0.
// - `p`: the SAID of the previous event.
//
// Changing an old event would change its SAID and break every later `p`, so the key event log
// (KEL) is tamper-evident from end to end.

use keri_cesr::crypto::digest::{Digest, DigestAlgorithm};
use keri_cesr::crypto::verifier::VerificationKey;
use keri_protocol::event::KeyEvent;
use keri_protocol::event::rotation::RotationBuilder;

fn commitment(key: &VerificationKey) -> Digest {
    Digest::derive(DigestAlgorithm::Blake3_256, key.qb64().unwrap().as_bytes())
}

/// Rotates the identifier incepted by `inception` to `new_key`, committing to `next_key`.
fn rotate(inception: &KeyEvent, new_key: &VerificationKey, next_key: &VerificationKey) -> KeyEvent {
    // TODO: Chain the rotation to the inception event: give it the inception event's SAID
    // and the right sequence number.
    RotationBuilder::new(
        inception.identifier().clone(),
        todo!(),
        todo!(),
        vec![new_key.clone()],
    )
    .next_key_digests(vec![commitment(next_key)])
    .build()
    .unwrap()
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
    use keri_protocol::prefix::PrefixDerivation;

    fn signer(seed: u8) -> Signer {
        Signer::from_seed(&[seed; 32], KeyTransferability::Transferable).unwrap()
    }

    #[test]
    fn rotate_once() {
        let (first, second, third) = (signer(1), signer(2), signer(3));

        let inception = InceptionBuilder::new(vec![first.verifier().clone()])
            .next_key_digests(vec![commitment(second.verifier())])
            .prefix_derivation(PrefixDerivation::Blake3_256)
            .build()
            .unwrap();

        // Rotate to the committed key and commit to the one after it.
        let rotation = rotate(&inception, second.verifier(), third.verifier());

        let prior = inception.said().qb64().unwrap();
        assert_eq!(rotation.sad().get_text("t"), Some("rot"));
        assert_eq!(rotation.sad().get_text("s"), Some("1"));
        assert_eq!(rotation.sad().get_text("p"), Some(prior.as_str()));
        // Rotation changes the keys, never the identifier.
        assert_eq!(rotation.identifier(), inception.identifier());
    }
}
