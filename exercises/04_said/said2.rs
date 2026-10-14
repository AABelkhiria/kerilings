// Verifying a SAID repeats its derivation: put the placeholder back, serialize, hash, and compare
// the result with the SAID the data claims. If a single byte of the data changed, the digests
// differ.
//
// `Said::verify` takes a `SaidVerification` policy. `SaidVerification::strict()` also requires the
// data's own `d` field to claim the SAID being checked, which is what you want for anything you
// receive from someone else.

use keri_protocol::said::{Said, SaidVerification};
use keri_protocol::serialization::Sad;

/// Returns `true` when `sad` carries, in its `d` field, the SAID that its contents derive.
fn is_authentic(sad: &Sad) -> bool {
    // TODO: Read the SAID the data claims from its `d` field, parse it, and verify it against
    // the data with the strict policy. Anything missing or unparsable is not authentic.
    todo!()
}

fn main() {
    // You can optionally experiment here.
}

#[cfg(test)]
mod tests {
    use super::*;
    use keri_cesr::crypto::digest::DigestAlgorithm;

    fn signed_up() -> Sad {
        let mut sad = Sad::new();
        sad.insert("d", "").unwrap();
        sad.insert("event", "signed up").unwrap();
        sad.insert("plan", "basic").unwrap();
        let computed = Said::compute(&sad, DigestAlgorithm::Blake3_256, "d").unwrap();
        computed.sad().clone()
    }

    #[test]
    fn untouched_data_is_authentic() {
        assert!(is_authentic(&signed_up()));
    }

    #[test]
    fn tampered_data_is_not() {
        let original = signed_up();
        let mut tampered = Sad::new();
        for (label, value) in original.entries() {
            if label == "plan" {
                tampered.insert(label, "premium").unwrap();
            } else {
                tampered.insert(label, value.clone()).unwrap();
            }
        }
        assert!(!is_authentic(&tampered));
    }

    #[test]
    fn data_without_a_said_is_not() {
        let mut sad = Sad::new();
        sad.insert("event", "signed up").unwrap();
        assert!(!is_authentic(&sad));
    }
}
