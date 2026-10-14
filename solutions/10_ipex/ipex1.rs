// IPEX (Issuance and Presentation EXchange) is how two controllers move a credential between
// them. It is a conversation of `exn` (exchange) messages, each naming the one before it in its
// `p` ("prior") field:
//
//     apply   the disclosee asks for a credential satisfying a schema    (no prior)
//     offer   the discloser answers with the credential                  (prior: the apply)
//     agree   the disclosee accepts                                      (prior: the offer)
//     grant   the discloser sends the credential and its proof           (prior: the agree)
//     admit   the disclosee acknowledges receipt                         (prior: the grant)
//
// Every message travels in an `IpexEnvelope`: who sends it, to whom, a human-readable text and a
// timestamp.
//
// Here a holder applies for a Legal Entity credential, the issuer offers one, and the holder
// agrees.

use keri_acdc::credential::{CredentialAttributes, CredentialBuilder, RegistryIdentifier};
use keri_acdc::ipex::{IpexEnvelope, IpexMessage, IpexRoute, agree, apply, offer};
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::said::Said;
use keri_protocol::serialization::{Sad, SadValue};

const ISSUER: &str = "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1";
const HOLDER: &str = "EKvn1M6shPLnXTb47bugVJblKMuWC0TcLIePP8p98Bby";
const SCHEMA: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
const STAMP: &str = "2023-08-23T15:16:07.553000+00:00";

fn envelope(sender: &str, recipient: &str, message: &str) -> IpexEnvelope {
    IpexEnvelope::new(
        IdentifierPrefix::from_qb64(sender).unwrap(),
        IdentifierPrefix::from_qb64(recipient).unwrap(),
        message,
        STAMP.parse().unwrap(),
    )
    .unwrap()
}

/// The holder's agree to the issuer's `offer`.
fn agree_to(offer: &IpexMessage) -> IpexMessage {
    agree(&envelope(HOLDER, ISSUER, "Agreeing"), offer.said()).unwrap()
}

fn main() {
    // You can optionally experiment here.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_offer_agree() {
        // The holder asks for a credential of this schema, with this LEI.
        let mut wanted = Sad::new();
        wanted
            .insert("LEI", SadValue::text("5493001KJTIIGC8Y1R17"))
            .unwrap();
        let apply = apply(
            &envelope(HOLDER, ISSUER, "Applying"),
            Said::from_qb64(SCHEMA).unwrap(),
            wanted,
        )
        .unwrap();

        // The issuer offers a credential that satisfies it.
        let credential = CredentialBuilder::new(
            IdentifierPrefix::from_qb64(ISSUER).unwrap(),
            RegistryIdentifier::from_qb64("EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df").unwrap(),
            Said::from_qb64(SCHEMA).unwrap(),
            CredentialAttributes::new(STAMP.parse().unwrap())
                .issuee(&IdentifierPrefix::from_qb64(HOLDER).unwrap())
                .unwrap()
                .timestamp()
                .unwrap()
                .text("LEI", "5493001KJTIIGC8Y1R17")
                .unwrap(),
        )
        .build()
        .unwrap();
        let offer = offer(
            &envelope(ISSUER, HOLDER, "Offering"),
            &credential,
            Some(apply.said()),
        )
        .unwrap();

        // The holder agrees to the offer.
        let agree = agree_to(&offer);

        assert_eq!(apply.route(), IpexRoute::Apply);
        assert_eq!(offer.route(), IpexRoute::Offer);
        assert_eq!(agree.route(), IpexRoute::Agree);
        assert_eq!(agree.exchange().route(), Some("/ipex/agree"));

        // Each message names the one before it.
        let prior =
            |message: &IpexMessage| message.exchange().sad().get_text("p").unwrap().to_owned();
        assert_eq!(prior(&apply), "");
        assert_eq!(prior(&offer), apply.said().qb64().unwrap());
        assert_eq!(prior(&agree), offer.said().qb64().unwrap());
    }
}
