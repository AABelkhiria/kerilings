// A basic prefix is a public key, so the identifier says nothing about the rest of the inception
// event. A self-addressing prefix is the SAID of the whole inception event instead: it binds the
// identifier to the first keys, the next-key commitments, the witnesses and every other field.
// Change any of them and you get a different identifier.
//
// Self-addressing prefixes start with `E`, the Blake3-256 code. In a self-addressing inception
// event the identifier (`i`) and the event's SAID (`d`) are the same value.
//
// `InceptionBuilder` picks a basic prefix for a single key unless told otherwise.

use keri_cesr::crypto::digest::{Digest, DigestAlgorithm};
use keri_cesr::crypto::signer::Signer;
use keri_cesr::crypto::verifier::KeyTransferability;
use keri_protocol::event::KeyEvent;
use keri_protocol::event::inception::InceptionBuilder;
use keri_protocol::prefix::PrefixDerivation;

/// Incepts an identifier with one current key and one committed next key.
fn incept() -> KeyEvent {
    let current = Signer::from_seed(&[1_u8; 32], KeyTransferability::Transferable).unwrap();
    let next = Signer::from_seed(&[2_u8; 32], KeyTransferability::Transferable).unwrap();
    let commitment = Digest::derive(
        DigestAlgorithm::Blake3_256,
        next.verifier().qb64().unwrap().as_bytes(),
    );

    InceptionBuilder::new(vec![current.verifier().clone()])
        .next_key_digests(vec![commitment])
        // TODO: Ask for a self-addressing prefix instead of the basic one.
        .build()
        .unwrap()
}

fn main() {
    // You can optionally experiment here.
}

#[cfg(test)]
mod tests {
    use super::*;
    use keri_protocol::prefix::{IdentifierPrefix, PrefixVerification};

    #[test]
    fn a_self_addressing_identifier() {
        let event = incept();

        let prefix = event.identifier().qb64().unwrap();
        assert!(matches!(
            event.identifier(),
            IdentifierPrefix::SelfAddressing(_)
        ));
        assert_eq!(prefix, event.said().qb64().unwrap());
        assert_eq!(prefix, "EM-WFDLO6Nx-gmVMPl4VhiKRhssBndTQB3hoCOG8gIz5");

        // Anyone holding the event can re-derive the prefix and check it.
        event
            .identifier()
            .verify(event.sad(), PrefixVerification::Strict)
            .unwrap();
    }
}
