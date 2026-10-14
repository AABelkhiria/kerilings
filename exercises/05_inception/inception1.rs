// An inception event (`icp`) creates a KERI identifier. It lists the identifier's first signing
// keys, and the identifier prefix is derived from the event itself.
//
// The simplest prefix is a basic one: with a single key and nothing else asking for a digest, the
// public key itself is the identifier. Its derivation code says what kind of key it is:
//
// - `D`: a transferable Ed25519 key, which can later rotate to new keys.
// - `B`: a non-transferable Ed25519 key, which can never rotate. Good for ephemeral identifiers
//   and witnesses.

use keri_cesr::crypto::signer::Signer;
use keri_cesr::crypto::verifier::KeyTransferability;

/// The signer of an identifier that must never rotate.
fn ephemeral_signer() -> Signer {
    // TODO: This identifier must never rotate. Pick the transferability that says so.
    Signer::from_seed(&[1_u8; 32], KeyTransferability::???).unwrap()
}

fn main() {
    // You can optionally experiment here.
}

#[cfg(test)]
mod tests {
    use super::*;
    use keri_protocol::event::inception::InceptionBuilder;

    #[test]
    fn a_non_transferable_identifier() {
        let signer = ephemeral_signer();
        let event = InceptionBuilder::new(vec![signer.verifier().clone()])
            .build()
            .unwrap();

        let prefix = event.identifier().qb64().unwrap();
        assert!(prefix.starts_with('B'));
        assert!(!event.identifier().is_transferable());
        // The key is the identifier.
        assert_eq!(prefix, signer.verifier().qb64().unwrap());
        assert_eq!(event.sequence_number(), 0);
    }
}
