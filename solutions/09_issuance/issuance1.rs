// Building a credential does not issue it. Issuing writes an `iss` event at position 0 of the
// credential's transaction event log, in the registry the credential names. Its `i` is the
// credential's SAID, its `ri` the registry, and its `dt` the credential's own timestamp, so the
// credential and its issuance always agree on when it happened.

use keri_acdc::credential::{
    Credential, CredentialAttributes, CredentialBuilder, RegistryIdentifier,
};
use keri_acdc::issuance::IssuanceEvent;
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::said::Said;

fn credential() -> Credential {
    let attributes = CredentialAttributes::new("2023-08-23T15:16:07.553000+00:00".parse().unwrap())
        .issuee(
            &IdentifierPrefix::from_qb64("EKvn1M6shPLnXTb47bugVJblKMuWC0TcLIePP8p98Bby").unwrap(),
        )
        .unwrap()
        .timestamp()
        .unwrap()
        .text("LEI", "5493001KJTIIGC8Y1R17")
        .unwrap();
    CredentialBuilder::new(
        IdentifierPrefix::from_qb64("EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1").unwrap(),
        RegistryIdentifier::from_qb64("EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df").unwrap(),
        Said::from_qb64("EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao").unwrap(),
        attributes,
    )
    .build()
    .unwrap()
}

/// The `iss` event that issues `credential`.
fn issue(credential: &Credential) -> IssuanceEvent {
    IssuanceEvent::for_credential(credential).unwrap()
}

fn main() {
    // You can optionally experiment here.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issuance_event() {
        let credential = credential();

        let issuance = issue(&credential);

        assert_eq!(issuance.sad().get_text("t"), Some("iss"));
        assert_eq!(issuance.sequence_number(), 0);
        assert_eq!(issuance.credential(), credential.said());
        assert_eq!(issuance.registry(), credential.registry());
        assert_eq!(issuance.timestamp(), credential.timestamp());
        assert_eq!(
            issuance.said().qb64().unwrap(),
            "ENf3IEYwYtFmlq5ZzoI-zFzeR7E3ZNRN2YH_0KAFbdJW",
        );
    }
}
