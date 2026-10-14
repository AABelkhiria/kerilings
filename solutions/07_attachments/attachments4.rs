// Messages other than key events, such as exchange messages (`exn`) between two identifiers, are
// signed by an identifier whose keys may since have rotated. So the signatures carry a seal naming
// the establishment event whose keys made them: the signer's identifier, that event's sequence
// number and its SAID. A verifier looks that event up in the signer's key event log and checks the
// signatures against its keys.
//
// The sealed group is introduced by the counter `-F`, followed by the seal and then the usual
// `-A` group of indexed signatures.
//
// Pipelined framing puts one more counter, `-V`, in front of all the attachments: it gives their
// total size in quadlets (groups of 4 characters), so a parser can skip them without reading them.

use keri_cesr::sequence::SequenceNumber;
use keri_protocol::attachment::SignatureSeal;
use keri_protocol::event::KeyEvent;

/// The seal that ties signatures to the keys of `inception`, the signer's inception event.
fn seal_to(inception: &KeyEvent) -> SignatureSeal {
    SignatureSeal::Event {
        identifier: inception.identifier().clone(),
        sequence_number: SequenceNumber::new(inception.sequence_number()),
        said: inception.said(),
    }
}

fn main() {
    // You can optionally experiment here.
}

#[cfg(test)]
mod tests {
    use super::*;
    use keri_cesr::crypto::signer::{SignaturePlacement, Signer};
    use keri_cesr::crypto::verifier::KeyTransferability;
    use keri_protocol::attachment::{AttachmentFraming, SignedMessageBuilder};
    use keri_protocol::event::Timestamp;
    use keri_protocol::event::exchange::ExchangeBuilder;
    use keri_protocol::event::inception::InceptionBuilder;
    use keri_protocol::prefix::PrefixDerivation;
    use keri_protocol::serialization::Sad;

    #[test]
    fn a_sealed_exchange_message() {
        let signer = Signer::from_seed(&[1_u8; 32], KeyTransferability::Transferable).unwrap();
        let sender = InceptionBuilder::new(vec![signer.verifier().clone()])
            .prefix_derivation(PrefixDerivation::Blake3_256)
            .build()
            .unwrap();
        let other = Signer::from_seed(&[2_u8; 32], KeyTransferability::Transferable).unwrap();
        let recipient = InceptionBuilder::new(vec![other.verifier().clone()])
            .prefix_derivation(PrefixDerivation::Blake3_256)
            .build()
            .unwrap();

        let mut payload = Sad::new();
        payload.insert("greeting", "hello").unwrap();
        let exchange = ExchangeBuilder::new(
            "/greet",
            sender.identifier().clone(),
            recipient.identifier().clone(),
            "2026-10-12T09:00:00.000000+00:00"
                .parse::<Timestamp>()
                .unwrap(),
        )
        .payload(payload)
        .build()
        .unwrap();

        let signature = signer
            .sign_indexed(exchange.raw(), SignaturePlacement::both_lists(0))
            .unwrap();
        let message = SignedMessageBuilder::new(exchange.serialized())
            .controller_signatures(vec![signature])
            .seal(seal_to(&sender))
            .framing(AttachmentFraming::Pipelined)
            .build()
            .unwrap();

        let attachments = String::from_utf8(message.attachments().to_vec()).unwrap();
        assert!(attachments.starts_with("-V"));
        let sealed = format!("-FAB{}", sender.identifier().qb64().unwrap());
        assert!(attachments[4..].starts_with(&sealed));
        assert!(attachments.contains("-AAB"));
        // The size counter counts every quadlet after itself.
        assert_eq!(attachments.len() % 4, 0);
    }
}
