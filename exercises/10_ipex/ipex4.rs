// Like the anchor in issuance3, an IPEX message is built unsigned. Before it travels, the sender
// signs its exact bytes with the keys of its identifier, and `SignedIpexMessage` pairs the
// message with those signatures. It refuses a message with no signature at all: the recipient
// would have no way to tell who sent it.
//
// Sign the holder's admit with the holder's key, at index 0.

use keri_acdc::ipex::{IpexEnvelope, IpexMessage, SignedIpexMessage, admit};
use keri_cesr::crypto::signature::IndexedSignature;
use keri_cesr::crypto::signer::{SignaturePlacement, Signer};
use keri_cesr::crypto::verifier::KeyTransferability;
use keri_protocol::event::inception::InceptionBuilder;
use keri_protocol::prefix::{IdentifierPrefix, PrefixDerivation};
use keri_protocol::said::Said;

const ISSUER: &str = "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1";
// The grant the holder is admitting, by its SAID.
const GRANT: &str = "EKBVSGFp6EedS8z2c_rT-L_GnBWxPdHN2c1UJYuQWdIl";

/// The holder's signatures on `message`, made with its only key, at index 0.
fn sign(signer: &Signer, message: &IpexMessage) -> Vec<IndexedSignature> {
    // TODO: Sign the message's exact bytes with the holder's key, at index 0.
    vec![]
}

fn main() {
    // You can optionally experiment here.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_the_admit() {
        let holder_signer =
            Signer::from_seed(&[2_u8; 32], KeyTransferability::Transferable).unwrap();
        let holder = InceptionBuilder::new(vec![holder_signer.verifier().clone()])
            .prefix_derivation(PrefixDerivation::Blake3_256)
            .build()
            .unwrap()
            .identifier()
            .clone();

        let envelope = IpexEnvelope::new(
            holder,
            IdentifierPrefix::from_qb64(ISSUER).unwrap(),
            "",
            "2023-08-23T15:17:00.000000+00:00".parse().unwrap(),
        )
        .unwrap();
        let message = admit(&envelope, Said::from_qb64(GRANT).unwrap()).unwrap();

        let signatures = sign(&holder_signer, &message);
        let signed = SignedIpexMessage::new(message, signatures).unwrap();

        assert_eq!(signed.signatures().len(), 1);
        let signature = &signed.signatures()[0];
        holder_signer
            .verifier()
            .verify(signature.raw(), signed.raw())
            .unwrap();
    }
}
