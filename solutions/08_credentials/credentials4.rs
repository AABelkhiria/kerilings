// A credential's status (issued or revoked) is not in the credential. It lives in a registry: a
// transaction event log (TEL) the issuer keeps for its credentials.
//
// A registry starts with a `vcp` registry inception event. The registry identifier is the
// self-addressing prefix of that event, a digest of the event itself, just as a KERI identifier
// can be a digest of its inception event. The issuer and a nonce go in, so one issuer can create
// many registries. `NB` ("no backers") says the registry's events are anchored only in the
// issuer's own key event log.
//
// Create a registry, then issue a credential into it.

use keri_acdc::credential::RegistryIdentifier;
use keri_protocol::event::KeyEvent;

const ISSUER: &str = "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1";
const NONCE: &str = "0ABhY2RjX3JlZ2lzdHJ5X25vbmNl";

/// The identifier of the registry that `vcp` incepts.
fn registry_identifier(vcp: &KeyEvent) -> RegistryIdentifier {
    RegistryIdentifier::from(vcp.identifier().clone())
}

fn main() {
    // You can optionally experiment here.
}

#[cfg(test)]
mod tests {
    use super::*;
    use keri_acdc::credential::{CredentialAttributes, CredentialBuilder};
    use keri_protocol::event::ConfigurationTrait;
    use keri_protocol::event::kind::EventKind;
    use keri_protocol::prefix::IdentifierPrefix;
    use keri_protocol::registry::RegistryInceptionBuilder;
    use keri_protocol::said::Said;

    #[test]
    fn registry_inception() {
        let issuer = IdentifierPrefix::from_qb64(ISSUER).unwrap();

        let vcp = RegistryInceptionBuilder::new(issuer.clone(), NONCE)
            .configuration(vec![ConfigurationTrait::NoBackers])
            .build()
            .unwrap();
        assert_eq!(vcp.kind(), EventKind::RegistryInception);
        assert_eq!(vcp.sad().get_text("ii"), Some(ISSUER));

        let registry = registry_identifier(&vcp);
        assert!(registry.prefix().is_digestive());
        assert_eq!(registry.prefix(), vcp.identifier());

        let credential = CredentialBuilder::new(
            issuer,
            registry.clone(),
            Said::from_qb64("EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao").unwrap(),
            CredentialAttributes::new("2023-08-23T15:16:07.553000+00:00".parse().unwrap()),
        )
        .build()
        .unwrap();
        assert_eq!(credential.registry(), &registry);
        assert_eq!(
            credential.sad().get_text("ri"),
            Some(registry.qb64().unwrap().as_str())
        );
    }
}
