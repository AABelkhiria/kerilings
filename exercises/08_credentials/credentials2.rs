// A credential carries two SAIDs, nested:
//
// - the attribute block's own `d` commits to the attributes;
// - the credential's `d` commits to the whole container, including the attribute block and so
//   including the first SAID.
//
// The attribute block has its own SAID so a holder can later disclose the credential without its
// attributes (only their digest) and still prove which attributes it carries.

use keri_acdc::credential::{
    Credential, CredentialAttributes, CredentialBuilder, RegistryIdentifier,
};
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

/// The SAID of the attribute block of `credential`.
fn attributes_said(credential: &Credential) -> Said {
    // TODO: This is the container's SAID. Get the attribute block's SAID instead.
    credential.said()
}

fn main() {
    // You can optionally experiment here.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_saids() {
        let credential = credential();

        let container_said = credential.said();
        let attributes_said = attributes_said(&credential);

        // The credential's `d` and the attribute block's `d`.
        let block = credential.attributes().unwrap();
        assert_eq!(
            credential.sad().get_text("d"),
            Some(container_said.qb64().unwrap().as_str())
        );
        assert_eq!(
            block.get_text("d"),
            Some(attributes_said.qb64().unwrap().as_str())
        );
        assert_eq!(
            attributes_said.qb64().unwrap(),
            "EK0GOjijKd8_RLYz9qDuuG29YbbXjU8yJuTQanf07b6P",
        );
    }
}
