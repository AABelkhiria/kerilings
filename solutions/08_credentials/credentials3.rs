// A SAID is a digest of the exact serialization, so field order is part of a credential's
// identity. The container's own fields are always written in the same order, but the attribute
// block is written in the order you add the attributes.
//
// The vLEI credentials place the issuance timestamp `dt` right after the issuee `i`, before the
// other attributes. Build the attribute block in that order so the credential has the SAID the
// vLEI ecosystem expects.

use keri_acdc::credential::CredentialAttributes;
use keri_protocol::prefix::IdentifierPrefix;

/// The attribute block of a Legal Entity credential, in vLEI order.
fn vlei_attributes(holder: &IdentifierPrefix) -> CredentialAttributes {
    CredentialAttributes::new("2023-08-23T15:16:07.553000+00:00".parse().unwrap())
        .issuee(holder)
        .unwrap()
        .timestamp()
        .unwrap()
        .text("LEI", "5493001KJTIIGC8Y1R17")
        .unwrap()
}

fn main() {
    // You can optionally experiment here.
}

#[cfg(test)]
mod tests {
    use super::*;
    use keri_acdc::credential::{CredentialBuilder, RegistryIdentifier};
    use keri_protocol::said::Said;

    #[test]
    fn field_order_is_identity() {
        let holder =
            IdentifierPrefix::from_qb64("EKvn1M6shPLnXTb47bugVJblKMuWC0TcLIePP8p98Bby").unwrap();

        let attributes = vlei_attributes(&holder);
        assert_eq!(attributes.labels(), ["d", "i", "dt", "LEI"]);

        let credential = CredentialBuilder::new(
            IdentifierPrefix::from_qb64("EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1").unwrap(),
            RegistryIdentifier::from_qb64("EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df").unwrap(),
            Said::from_qb64("EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao").unwrap(),
            attributes,
        )
        .build()
        .unwrap();

        assert_eq!(
            credential.said().qb64().unwrap(),
            "EMwcsEMUEruPXVwPCW7zmqmN8m0I3CihxolBm-RDrsJo",
        );
    }
}
