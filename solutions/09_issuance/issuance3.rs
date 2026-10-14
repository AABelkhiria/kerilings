// The anchoring interaction event means nothing until the issuer signs it. keri-acdc builds every
// artifact unsigned and leaves signing to whoever holds the keys: here a `Signer`, in a Signify
// client its key manager, in a multisig group every member.
//
// A controller signature on a key event is *indexed*: it says which of the event's signing keys
// produced it. This issuer has one key, at index 0 of both its current key list and (for a
// rotation) its prior next-key list, so `SignaturePlacement::both_lists(0)`.
//
// `SignedAnchor` pairs the event with its signatures. Together with the credential and its
// issuance, it makes the `IssuanceArtifacts`: everything a holder later needs to prove the
// credential was issued.

use keri_acdc::credential::{CredentialAttributes, CredentialBuilder, RegistryIdentifier};
use keri_acdc::ipex::Disclosure;
use keri_acdc::issuance::{IssuanceArtifacts, IssuanceEvent};
use keri_acdc::transaction::{AnchorState, SignedAnchor, anchor_event};
use keri_cesr::crypto::signature::IndexedSignature;
use keri_cesr::crypto::signer::{SignaturePlacement, Signer};
use keri_cesr::crypto::verifier::KeyTransferability;
use keri_protocol::event::KeyEvent;
use keri_protocol::event::inception::InceptionBuilder;
use keri_protocol::prefix::PrefixDerivation;
use keri_protocol::said::Said;

/// The issuer's signature on `anchor`, with its only key, at index 0.
fn sign_anchor(signer: &Signer, anchor: &KeyEvent) -> IndexedSignature {
    signer
        .sign_indexed(anchor.raw(), SignaturePlacement::both_lists(0))
        .unwrap()
}

fn main() {
    // You can optionally experiment here.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_the_anchor() {
        let signer = Signer::from_seed(&[1_u8; 32], KeyTransferability::Transferable).unwrap();
        let icp = InceptionBuilder::new(vec![signer.verifier().clone()])
            .prefix_derivation(PrefixDerivation::Blake3_256)
            .build()
            .unwrap();
        let issuer = icp.identifier().clone();

        let credential = CredentialBuilder::new(
            issuer.clone(),
            RegistryIdentifier::from_qb64("EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df").unwrap(),
            Said::from_qb64("EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao").unwrap(),
            CredentialAttributes::new("2023-08-23T15:16:07.553000+00:00".parse().unwrap()),
        )
        .build()
        .unwrap();
        let issuance = IssuanceEvent::for_credential(&credential).unwrap();
        let anchor = anchor_event(
            &AnchorState::new(issuer, icp.sequence_number(), icp.said()),
            &issuance.seal(),
        )
        .unwrap();

        let signature = sign_anchor(&signer, &anchor);

        // The signature covers exactly the anchor's bytes.
        signer
            .verifier()
            .verify(signature.raw(), anchor.raw())
            .unwrap();
        assert_eq!(signature.index(), 0);

        let artifacts = IssuanceArtifacts {
            credential,
            issuance,
            anchor: SignedAnchor::new(anchor, vec![signature]),
        };

        // A disclosure needs a signed anchor: it is what chains the credential to the issuer's
        // keys.
        let disclosure = Disclosure::from_issuance(&artifacts).unwrap();
        assert_eq!(disclosure.anchor().raw(), artifacts.anchor.event.raw());
    }
}
