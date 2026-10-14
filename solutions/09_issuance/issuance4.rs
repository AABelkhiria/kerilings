// Revoking a credential appends a `rev` event to its transaction event log. Like every event
// after the first, it names the event before it in its `p` ("prior") field, so the log is a
// hash chain: `iss` at position 0, then `rev` at position 1 pointing at the `iss`.
//
// The credential itself does not change: a revoked credential is byte-identical to an issued
// one. Only its log says which it is.
//
// The issuer anchors the revocation exactly as it anchored the issuance, in a new interaction
// event one past its latest key event.

use keri_acdc::credential::{
    Credential, CredentialAttributes, CredentialBuilder, RegistryIdentifier,
};
use keri_acdc::issuance::IssuanceEvent;
use keri_acdc::revocation::{RevocationEvent, RevocationEventBuilder};
use keri_acdc::transaction::{AnchorState, anchor_event};
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::said::Said;

const ISSUER: &str = "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1";
const STAMP: &str = "2023-08-23T15:16:07.553000+00:00";

fn credential() -> Credential {
    CredentialBuilder::new(
        IdentifierPrefix::from_qb64(ISSUER).unwrap(),
        RegistryIdentifier::from_qb64("EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df").unwrap(),
        Said::from_qb64("EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao").unwrap(),
        CredentialAttributes::new(STAMP.parse().unwrap()),
    )
    .build()
    .unwrap()
}

/// The `rev` event that revokes `credential`, issued by `issuance`.
fn revoke(credential: &Credential, issuance: &IssuanceEvent) -> RevocationEvent {
    RevocationEventBuilder::new(
        credential.said(),
        credential.registry().clone(),
        issuance.said(),
        "2024-01-01T00:00:00.000000+00:00".parse().unwrap(),
    )
    .build()
    .unwrap()
}

fn main() {
    // You can optionally experiment here.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revoke_a_credential() {
        let credential = credential();
        let issuance = IssuanceEvent::for_credential(&credential).unwrap();

        let revocation = revoke(&credential, &issuance);

        assert_eq!(revocation.sad().get_text("t"), Some("rev"));
        assert_eq!(revocation.sequence_number(), 1);
        assert_eq!(revocation.credential(), credential.said());
        assert_eq!(revocation.prior(), issuance.said());

        // The issuer anchored the issuance at sequence number 1; its latest event is that anchor.
        let issuer = IdentifierPrefix::from_qb64(ISSUER).unwrap();
        let issuance_anchor = anchor_event(
            &AnchorState::new(issuer.clone(), 0, Said::from_qb64(ISSUER).unwrap()),
            &issuance.seal(),
        )
        .unwrap();

        let revocation_anchor = anchor_event(
            &AnchorState::new(
                issuer,
                issuance_anchor.sequence_number(),
                issuance_anchor.said(),
            ),
            &revocation.seal(),
        )
        .unwrap();
        assert_eq!(revocation_anchor.sequence_number(), 2);
        assert_eq!(revocation.seal().sequence_number(), 1);
    }
}
