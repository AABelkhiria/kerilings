// A verifier receives an event and its indexed signatures. For each signature it looks up the key
// at the signature's index in the event's own key list (`k`) and checks the signature over the
// exact bytes of the event.
//
// Nothing outside the event is needed for an inception event: its keys are inside it, and its
// identifier is derived from it.

use keri_cesr::crypto::signature::IndexedSignature;
use keri_protocol::serialization::SerializedEvent;

/// Returns `true` when every signature verifies against the key at its index in `event`.
fn signatures_verify(event: &[u8], signatures: &[IndexedSignature]) -> bool {
    let Ok(parsed) = SerializedEvent::parse(event) else {
        return false;
    };
    let Ok(keys) = parsed.verification_keys() else {
        return false;
    };
    !signatures.is_empty()
        && signatures.iter().all(|signature| {
            let Ok(index) = usize::try_from(signature.index()) else {
                return false;
            };
            keys.get(index)
                .is_some_and(|key| key.verify(signature.raw(), event).is_ok())
        })
}

fn main() {
    // You can optionally experiment here.
}

#[cfg(test)]
mod tests {
    use super::*;
    use keri_cesr::crypto::signer::{SignaturePlacement, Signer};
    use keri_cesr::crypto::verifier::KeyTransferability;
    use keri_protocol::event::inception::InceptionBuilder;

    fn signer(seed: u8) -> Signer {
        Signer::from_seed(&[seed; 32], KeyTransferability::Transferable).unwrap()
    }

    fn event() -> Vec<u8> {
        InceptionBuilder::new(vec![
            signer(1).verifier().clone(),
            signer(2).verifier().clone(),
        ])
        .build()
        .unwrap()
        .raw()
        .to_vec()
    }

    fn sign(seed: u8, index: u32, event: &[u8]) -> IndexedSignature {
        signer(seed)
            .sign_indexed(event, SignaturePlacement::both_lists(index))
            .unwrap()
    }

    #[test]
    fn both_keys_signed() {
        let event = event();
        assert!(signatures_verify(
            &event,
            &[sign(1, 0, &event), sign(2, 1, &event)]
        ));
    }

    #[test]
    fn a_signature_at_the_wrong_index_fails() {
        let event = event();
        assert!(!signatures_verify(&event, &[sign(2, 0, &event)]));
    }

    #[test]
    fn a_stranger_cannot_sign() {
        let event = event();
        assert!(!signatures_verify(&event, &[sign(9, 0, &event)]));
    }

    #[test]
    fn a_changed_event_fails() {
        let event = event();
        let signature = sign(1, 0, &event);
        let tampered = String::from_utf8(event)
            .unwrap()
            .replace(r#""bt":"0""#, r#""bt":"1""#);
        assert!(!signatures_verify(tampered.as_bytes(), &[signature]));
    }
}
