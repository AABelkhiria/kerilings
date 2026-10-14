// The holder closes the conversation with an admit: "I received the credential". It is addressed
// back to the issuer and names the grant as its prior, so the issuer knows which grant was
// accepted.
//
// Who sends a message matters: the envelope's sender becomes the exchange's `i`, and the
// recipient goes in the attribute block's `i`.

use keri_acdc::ipex::{IpexEnvelope, IpexRoute, admit};
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::said::Said;

const ISSUER: &str = "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1";
const HOLDER: &str = "EKvn1M6shPLnXTb47bugVJblKMuWC0TcLIePP8p98Bby";
// The grant the issuer sent, by its SAID. Any SAID will do here: in ipex2 it was `grant.said()`.
const GRANT: &str = "EKBVSGFp6EedS8z2c_rT-L_GnBWxPdHN2c1UJYuQWdIl";

/// The envelope of the holder's admit.
fn admit_envelope() -> IpexEnvelope {
    IpexEnvelope::new(
        // TODO: Who sends the admit, and to whom?
        IdentifierPrefix::from_qb64(ISSUER).unwrap(),
        IdentifierPrefix::from_qb64(HOLDER).unwrap(),
        "Received, thanks",
        "2023-08-23T15:17:00.000000+00:00".parse().unwrap(),
    )
    .unwrap()
}

fn main() {
    // You can optionally experiment here.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admit_the_grant() {
        let envelope = admit_envelope();

        let admit = admit(&envelope, Said::from_qb64(GRANT).unwrap()).unwrap();

        assert_eq!(admit.route(), IpexRoute::Admit);
        assert_eq!(admit.exchange().sender(), Some(HOLDER));
        assert_eq!(admit.exchange().recipient(), Some(ISSUER));
        assert_eq!(admit.exchange().sad().get_text("p"), Some(GRANT));
        assert!(admit.attachments().is_empty());
    }
}
