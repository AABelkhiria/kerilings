// Nobody trusts an `iss` event on its own word. The issuer anchors it in its own key event log
// (KEL): it appends an interaction event (`ixn`) carrying a seal `{i, s, d}`, naming the
// transaction event's credential, position and SAID. Once the issuer signs that interaction
// event, a verifier who trusts the KEL can follow the seal to the issuance, then to the
// credential.
//
// `anchor_event` builds that interaction event from the issuer's current key state: its
// identifier, the sequence number of its latest event, and that event's SAID. The anchor goes
// one past it.
//
// Here the issuer has just been incepted: its KEL holds only its inception event.

use keri_acdc::credential::{CredentialAttributes, CredentialBuilder, RegistryIdentifier};
use keri_acdc::issuance::IssuanceEvent;
use keri_acdc::transaction::{AnchorState, anchor_event};
use keri_cesr::crypto::signer::Signer;
use keri_cesr::crypto::verifier::KeyTransferability;
use keri_protocol::event::KeyEvent;
use keri_protocol::event::inception::InceptionBuilder;
use keri_protocol::event::kind::EventKind;
use keri_protocol::prefix::PrefixDerivation;
use keri_protocol::said::Said;

fn issuer_inception() -> KeyEvent {
    let signer = Signer::from_seed(&[1_u8; 32], KeyTransferability::Transferable).unwrap();
    InceptionBuilder::new(vec![signer.verifier().clone()])
        .prefix_derivation(PrefixDerivation::Blake3_256)
        .build()
        .unwrap()
}

/// The issuer's key state right after `icp`, its inception event.
fn issuer_state(icp: &KeyEvent) -> AnchorState {
    AnchorState::new(icp.identifier().clone(), icp.sequence_number(), icp.said())
}

fn main() {
    // You can optionally experiment here.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchor_the_issuance() {
        let icp = issuer_inception();
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

        let anchor = anchor_event(&issuer_state(&icp), &issuance.seal()).unwrap();

        assert_eq!(anchor.kind(), EventKind::Interaction);
        assert_eq!(anchor.identifier(), &issuer);
        assert_eq!(anchor.sequence_number(), 1);
        assert_eq!(
            anchor.sad().get_text("p"),
            Some(icp.said().qb64().unwrap().as_str())
        );

        // The seal names the credential, the position of the issuance in its log, and its SAID.
        let seal = issuance.seal();
        assert_eq!(seal.credential(), credential.said());
        assert_eq!(seal.sequence_number(), 0);
        assert_eq!(seal.said(), issuance.said());
    }
}
