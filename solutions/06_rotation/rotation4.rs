// A delegated identifier is created by a delegated inception event (`dip`), which names its
// delegator in the `di` field. The delegate's event alone is not enough: the delegator approves
// it by anchoring a seal to it in the delegator's own key event log, usually with an interaction
// event. The seal names the delegate's event by identifier (`i`), sequence number (`s`, in
// hexadecimal) and SAID (`d`).
//
// A verifier accepts the delegate only after finding that seal, so the delegator stays in control
// of who acts on its behalf.

use keri_cesr::crypto::signer::Signer;
use keri_cesr::crypto::verifier::KeyTransferability;
use keri_protocol::event::KeyEvent;
use keri_protocol::event::inception::InceptionBuilder;
use keri_protocol::event::interaction::InteractionBuilder;
use keri_protocol::prefix::PrefixDerivation;
use keri_protocol::serialization::Sad;

/// Returns the seal a delegator anchors to approve `event`.
fn approval_seal(event: &KeyEvent) -> Sad {
    let mut seal = Sad::new();
    seal.insert("i", event.identifier().qb64().unwrap())
        .unwrap();
    seal.insert("s", format!("{:x}", event.sequence_number()))
        .unwrap();
    seal.insert("d", event.said().qb64().unwrap()).unwrap();
    seal
}

fn main() {
    // You can optionally experiment here.
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> keri_cesr::crypto::verifier::VerificationKey {
        Signer::from_seed(&[seed; 32], KeyTransferability::Transferable)
            .unwrap()
            .verifier()
            .clone()
    }

    #[test]
    fn delegate_and_approve() {
        let delegator = InceptionBuilder::new(vec![key(1)])
            .prefix_derivation(PrefixDerivation::Blake3_256)
            .build()
            .unwrap();

        let delegate = InceptionBuilder::new(vec![key(2)])
            .delegator(delegator.identifier().clone())
            .build()
            .unwrap();
        assert_eq!(delegate.sad().get_text("t"), Some("dip"));
        let delegator_prefix = delegator.identifier().qb64().unwrap();
        assert_eq!(
            delegate.sad().get_text("di"),
            Some(delegator_prefix.as_str())
        );

        let approval = InteractionBuilder::new(delegator.identifier().clone(), delegator.said(), 1)
            .anchors(vec![approval_seal(&delegate)])
            .build()
            .unwrap();

        let raw = String::from_utf8(approval.raw().to_vec()).unwrap();
        let seal = format!(
            r#""a":[{{"i":"{}","s":"0","d":"{}"}}]"#,
            delegate.identifier().qb64().unwrap(),
            delegate.said().qb64().unwrap(),
        );
        assert!(raw.contains(&seal));
    }
}
