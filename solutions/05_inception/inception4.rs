// An identifier can have several signing keys, held by different people or devices. Its signing
// threshold (`kt`) says which combinations of their signatures are enough.
//
// - A numeric threshold such as `2` means any two of the keys.
// - A weighted threshold gives each key a fraction, in key order, and is met once the fractions
//   of the keys that signed add up to at least 1. With `["1/2", "1/2", "1/2"]`, any two of the
//   three keys are enough.
//
// `SigningThreshold::from_json` parses the same JSON you see in an event's `kt` field.

use keri_cesr::crypto::signer::Signer;
use keri_cesr::crypto::verifier::KeyTransferability;
use keri_protocol::event::inception::InceptionBuilder;
use keri_protocol::threshold::SigningThreshold;

/// Key 0 can sign alone; keys 1 and 2 can only sign together.
fn weights() -> SigningThreshold {
    SigningThreshold::from_json(r#"["1","1/2","1/2"]"#).unwrap()
}

fn main() {
    // You can optionally experiment here.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_weighted_threshold() {
        let threshold = weights();

        assert!(threshold.is_weighted());
        assert!(threshold.is_satisfied_by(&[0]).unwrap());
        assert!(threshold.is_satisfied_by(&[1, 2]).unwrap());
        assert!(!threshold.is_satisfied_by(&[1]).unwrap());
        assert!(!threshold.is_satisfied_by(&[2]).unwrap());
    }

    #[test]
    fn three_keys_one_event() {
        let keys: Vec<_> = (1..=3_u8)
            .map(|seed| {
                Signer::from_seed(&[seed; 32], KeyTransferability::Transferable)
                    .unwrap()
                    .verifier()
                    .clone()
            })
            .collect();
        let threshold = weights();

        let event = InceptionBuilder::new(keys)
            .signing_threshold(threshold)
            .build()
            .unwrap();

        // Three keys cannot be one basic prefix, so the identifier is self-addressing.
        assert!(event.identifier().qb64().unwrap().starts_with('E'));
        let raw = String::from_utf8(event.raw().to_vec()).unwrap();
        assert!(raw.contains(r#""kt":["1","1/2","1/2"]"#));
    }
}
