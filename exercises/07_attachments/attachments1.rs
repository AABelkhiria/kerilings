// An event means nothing until its controller signs it. A KERI message travels as the serialized
// event followed by its attachments: CESR groups of signatures appended after the JSON.
//
// The controller's signatures go in a group introduced by the counter `-A` and a two-character
// count, so one signature is `-AAB` (`B` is 1 in Base64). Each signature is indexed: it records the
// position of the signing key in the event's key list (`k`), so a verifier knows which key to
// check it against.
//
// `SignaturePlacement::both_lists(0)` means key 0 of the current list, which is also key 0 of the
// list the previous event committed to.

use keri_cesr::crypto::signature::IndexedSignature;
use keri_cesr::crypto::signer::{SignaturePlacement, Signer};
use keri_protocol::event::KeyEvent;

/// The controller's signature on `event`, made with its key 0.
fn sign_event(signer: &Signer, event: &KeyEvent) -> IndexedSignature {
    // TODO: Sign the serialized event with `signer`, whose key is key 0 in the event.
}

fn main() {
    // You can optionally experiment here.
}

#[cfg(test)]
mod tests {
    use super::*;
    use keri_cesr::crypto::verifier::KeyTransferability;
    use keri_protocol::attachment::SignedMessageBuilder;
    use keri_protocol::event::inception::InceptionBuilder;

    #[test]
    fn sign_an_inception_event() {
        let signer = Signer::from_seed(&[1_u8; 32], KeyTransferability::Transferable).unwrap();
        let event = InceptionBuilder::new(vec![signer.verifier().clone()])
            .build()
            .unwrap();

        let signature = sign_event(&signer, &event);

        let message = SignedMessageBuilder::new(event.serialized())
            .controller_signatures(vec![signature.clone()])
            .build()
            .unwrap();

        // The event comes first, unchanged; the attachments follow.
        assert!(message.as_bytes().starts_with(event.raw()));
        assert_eq!(message.event(), event.raw());
        assert!(message.attachments().starts_with(b"-AAB"));
        assert_eq!(signature.index(), 0);
        let expected = format!("-AAB{}", signature.qb64().unwrap());
        assert_eq!(message.attachments(), expected.as_bytes());
        // The signature is over the event's exact bytes.
        signer
            .verifier()
            .verify(signature.raw(), event.raw())
            .unwrap();
    }
}
