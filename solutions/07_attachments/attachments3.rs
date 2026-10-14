// Witnesses are servers an identifier names in its establishment events (`b`). They receive each
// event, check it, and sign a receipt; a verifier trusts an event once enough witnesses (the
// witness threshold, `bt` or "toad") have receipted it.
//
// A witness is identified by a non-transferable key (`B...`), so its receipt is a couple: the
// witness's key followed by its plain (unindexed) signature over the event. Receipt couples go in
// a group introduced by the counter `-C`.

use keri_cesr::crypto::signer::Signer;
use keri_protocol::attachment::ReceiptCouple;
use keri_protocol::event::KeyEvent;

/// The receipt `witness` gives for `event`.
fn receipt(witness: &Signer, event: &KeyEvent) -> ReceiptCouple {
    let signature = witness.sign_unindexed(event.raw()).unwrap();
    ReceiptCouple::new(witness.verifier().clone(), signature).unwrap()
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
    use keri_protocol::prefix::{BasicPrefix, IdentifierPrefix};

    #[test]
    fn two_witness_receipts() {
        let controller = Signer::from_seed(&[1_u8; 32], KeyTransferability::Transferable).unwrap();
        let witnesses: Vec<Signer> = [7_u8, 8]
            .iter()
            .map(|seed| {
                Signer::from_seed(&[*seed; 32], KeyTransferability::NonTransferable).unwrap()
            })
            .collect();
        let prefixes: Vec<IdentifierPrefix> = witnesses
            .iter()
            .map(|witness| {
                IdentifierPrefix::Basic(BasicPrefix::new(witness.verifier().clone()).unwrap())
            })
            .collect();

        let event = InceptionBuilder::new(vec![controller.verifier().clone()])
            .witnesses(prefixes)
            .witness_threshold(2)
            .build()
            .unwrap();
        assert_eq!(event.sad().get_text("bt"), Some("2"));

        let receipts: Vec<ReceiptCouple> = witnesses
            .iter()
            .map(|witness| receipt(witness, &event))
            .collect();

        let message = SignedMessageBuilder::new(event.serialized())
            .receipt_couples(receipts)
            .build()
            .unwrap();

        // `C` for receipt couples, then a count of 2.
        assert!(message.attachments().starts_with(b"-CAC"));
    }

    #[test]
    fn a_transferable_key_cannot_receipt() {
        let witness = Signer::from_seed(&[7_u8; 32], KeyTransferability::Transferable).unwrap();
        let signature = witness.sign_unindexed(b"any event").unwrap();
        assert!(ReceiptCouple::new(witness.verifier().clone(), signature).is_err());
    }
}
