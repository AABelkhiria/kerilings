// The grant is the message that actually hands over a credential. It embeds three artifacts, and
// attaches the proof that chains each to the next:
//
//     acdc   the credential          attached: a seal naming its `iss` event
//     iss    the issuance event      attached: a seal naming the issuer's anchoring event
//     anc    the anchoring event     attached: the issuer's signature over it
//
// So the recipient can walk from the credential to a key event signed by the issuer, and check
// that signature against the issuer's key event log. A `Disclosure` holds those three artifacts
// and their attachments; `Disclosure::from_issuance` derives it from what issuing produced.
//
// A grant may open a conversation, with no prior agree: that is how an issuer usually sends a
// freshly issued credential to its holder.

use keri_acdc::credential::{CredentialAttributes, CredentialBuilder, RegistryIdentifier};
use keri_acdc::ipex::{Disclosure, IpexEnvelope, IpexRoute, grant};
use keri_acdc::issuance::{IssuanceArtifacts, IssuanceEvent};
use keri_acdc::transaction::{AnchorState, SignedAnchor, anchor_event};
use keri_cesr::crypto::signer::{SignaturePlacement, Signer};
use keri_cesr::crypto::verifier::KeyTransferability;
use keri_protocol::event::inception::InceptionBuilder;
use keri_protocol::prefix::{IdentifierPrefix, PrefixDerivation};
use keri_protocol::said::Said;

const HOLDER: &str = "EKvn1M6shPLnXTb47bugVJblKMuWC0TcLIePP8p98Bby";
const STAMP: &str = "2023-08-23T15:16:07.553000+00:00";

// Everything issuance3 built: a credential, its issuance and the issuer's signed anchor.
fn issue() -> (IdentifierPrefix, IssuanceArtifacts) {
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
        CredentialAttributes::new(STAMP.parse().unwrap())
            .issuee(&IdentifierPrefix::from_qb64(HOLDER).unwrap())
            .unwrap(),
    )
    .build()
    .unwrap();
    let issuance = IssuanceEvent::for_credential(&credential).unwrap();
    let anchor = anchor_event(
        &AnchorState::new(issuer.clone(), icp.sequence_number(), icp.said()),
        &issuance.seal(),
    )
    .unwrap();
    let signature = signer
        .sign_indexed(anchor.raw(), SignaturePlacement::both_lists(0))
        .unwrap();
    let artifacts = IssuanceArtifacts {
        credential,
        issuance,
        anchor: SignedAnchor::new(anchor, vec![signature]),
    };
    (issuer, artifacts)
}

/// The disclosure of everything issuing produced.
fn disclose(artifacts: &IssuanceArtifacts) -> Disclosure {
    Disclosure::from_issuance(artifacts).unwrap()
}

fn main() {
    // You can optionally experiment here.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_a_credential() {
        let (issuer, artifacts) = issue();
        let envelope = IpexEnvelope::new(
            issuer,
            IdentifierPrefix::from_qb64(HOLDER).unwrap(),
            "Here is your credential",
            STAMP.parse().unwrap(),
        )
        .unwrap();

        let disclosure = disclose(&artifacts);
        let grant = grant(&envelope, &disclosure, None).unwrap();

        assert_eq!(grant.route(), IpexRoute::Grant);
        assert_eq!(grant.exchange().sad().get_text("p"), Some(""));

        // The three embeds, by label, are the artifacts issuing produced.
        let embeds = grant.exchange().sad().get("e").unwrap().as_map().unwrap();
        let said_of = |label: &str| {
            embeds
                .get(label)
                .unwrap()
                .as_map()
                .unwrap()
                .get_text("d")
                .unwrap()
        };
        assert_eq!(said_of("acdc"), artifacts.credential.said().qb64().unwrap());
        assert_eq!(said_of("iss"), artifacts.issuance.said().qb64().unwrap());
        assert_eq!(
            said_of("anc"),
            artifacts.anchor.event.said().qb64().unwrap()
        );

        // Only a grant carries attachments: one pathed group per embed.
        let attachments = String::from_utf8(grant.attachments().to_vec()).unwrap();
        assert!(attachments.contains("-e-acdc"));
        assert!(attachments.contains("-e-iss"));
        assert!(attachments.contains("-e-anc"));
    }
}
