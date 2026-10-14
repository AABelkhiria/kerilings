// An interaction event (`ixn`) does not change keys. It anchors data in the key event log: its
// `a` field lists seals, small records that commit to something outside the log by its SAID.
// Signing the interaction event signs the seal, and the log fixes when it happened.
//
// A common seal names a SAID with `d`. Seals that point at another identifier's event use `i`
// (identifier), `s` (sequence number, in hexadecimal) and `d` (the event's SAID).
//
// Like a rotation, an interaction event carries the next sequence number and the previous event's
// SAID.

use keri_protocol::said::Said;
use keri_protocol::serialization::Sad;

/// A seal that commits to the document with SAID `document`.
fn seal(document: &Said) -> Sad {
    let mut seal = Sad::new();
    // TODO: Make the seal name the document by its SAID.
    seal
}

fn main() {
    // You can optionally experiment here.
}

#[cfg(test)]
mod tests {
    use super::*;
    use keri_cesr::crypto::digest::DigestAlgorithm;
    use keri_cesr::crypto::signer::Signer;
    use keri_cesr::crypto::verifier::KeyTransferability;
    use keri_protocol::event::inception::InceptionBuilder;
    use keri_protocol::event::interaction::InteractionBuilder;
    use keri_protocol::prefix::PrefixDerivation;

    #[test]
    fn anchor_a_document() {
        let signer = Signer::from_seed(&[1_u8; 32], KeyTransferability::Transferable).unwrap();
        let inception = InceptionBuilder::new(vec![signer.verifier().clone()])
            .prefix_derivation(PrefixDerivation::Blake3_256)
            .build()
            .unwrap();

        // Some document, identified by its SAID.
        let mut document = Sad::new();
        document.insert("d", "").unwrap();
        document
            .insert("title", "Board minutes, 2026-10-01")
            .unwrap();
        let document = Said::compute(&document, DigestAlgorithm::Blake3_256, "d").unwrap();

        let interaction =
            InteractionBuilder::new(inception.identifier().clone(), inception.said(), 1)
                .anchors(vec![seal(document.said())])
                .build()
                .unwrap();

        assert_eq!(interaction.sad().get_text("t"), Some("ixn"));
        assert_eq!(interaction.sequence_number(), 1);
        let raw = String::from_utf8(interaction.raw().to_vec()).unwrap();
        let anchored = format!(r#""a":[{{"d":"{}"}}]"#, document.said().qb64().unwrap());
        assert!(raw.contains(&anchored));
    }
}
