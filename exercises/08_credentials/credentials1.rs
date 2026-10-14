// An ACDC (Authentic Chained Data Container) is a JSON document an issuer makes about a subject.
// It names:
//
// - `i`: the issuer, a KERI identifier;
// - `ri`: the registry whose transaction log records whether the credential is issued or revoked;
// - `s`: the schema the credential claims to satisfy, by the schema's SAID;
// - `a`: the attribute block, which names the subject (the "issuee") in its own `i` field.
//
// `CredentialBuilder` assembles one, and `build` derives its SAID: the digest that is the
// credential's identity.
//
// This credential is the one signify-ts's own tests issue: a Legal Entity credential carrying an
// LEI, issued to a holder.

use keri_acdc::credential::CredentialAttributes;
use keri_protocol::prefix::IdentifierPrefix;

const ISSUER: &str = "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1";
const HOLDER: &str = "EKvn1M6shPLnXTb47bugVJblKMuWC0TcLIePP8p98Bby";
const REGISTRY: &str = "EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df";
const SCHEMA: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
const STAMP: &str = "2023-08-23T15:16:07.553000+00:00";

/// The attribute block of a Legal Entity credential issued to `holder`.
fn legal_entity_attributes(holder: &IdentifierPrefix) -> CredentialAttributes {
    // TODO: Name the holder as the credential's issuee, before the timestamp.
    CredentialAttributes::new(STAMP.parse().unwrap())
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
    fn legal_entity_credential() {
        let holder = IdentifierPrefix::from_qb64(HOLDER).unwrap();

        let credential = CredentialBuilder::new(
            IdentifierPrefix::from_qb64(ISSUER).unwrap(),
            RegistryIdentifier::from_qb64(REGISTRY).unwrap(),
            Said::from_qb64(SCHEMA).unwrap(),
            legal_entity_attributes(&holder),
        )
        .build()
        .unwrap();

        let block = credential.attributes().unwrap();
        assert_eq!(block.get_text("i"), Some(HOLDER));
        assert_eq!(block.get_text("LEI"), Some("5493001KJTIIGC8Y1R17"));
        assert_eq!(
            credential.said().qb64().unwrap(),
            "EMwcsEMUEruPXVwPCW7zmqmN8m0I3CihxolBm-RDrsJo",
        );
    }
}
