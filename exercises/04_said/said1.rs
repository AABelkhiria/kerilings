// A SAID (self-addressing identifier) is a digest that a piece of data carries about itself.
//
// The data cannot contain its own digest before the digest exists, so the SAID is computed in
// three steps:
//
// 1. Fill the identifier field (by convention `d`) with a placeholder of `#` characters exactly
//    as wide as the finished SAID: 44 characters for a Blake3-256 digest.
// 2. Serialize the data and hash it.
// 3. Replace the placeholder with the qb64 of the digest.
//
// Anyone can repeat steps 1 and 2 and compare. `Said::compute` does all three, but the field has
// to exist already: it never adds one, because adding a field would change the bytes being
// committed to.

use keri_cesr::crypto::digest::DigestAlgorithm;
use keri_protocol::said::Said;
use keri_protocol::serialization::Sad;

/// The data to give a SAID to.
fn profile() -> Sad {
    let mut sad = Sad::new();
    // TODO: `Said::compute` fails because the data has no field to hold its SAID. Add an
    // empty `d` field as the first field.
    sad.insert("name", "John Jones").unwrap();
    sad.insert("role", "Founder").unwrap();
    sad
}

fn main() {
    // You can optionally experiment here.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_a_said() {
        let computed = Said::compute(&profile(), DigestAlgorithm::Blake3_256, "d").unwrap();
        let said = computed.said().qb64().unwrap();

        // A Blake3-256 SAID is 44 characters and starts with its derivation code, `E`.
        assert_eq!(said.len(), 44);
        assert!(said.starts_with('E'));
        // The completed data carries its own SAID.
        assert_eq!(computed.sad().get_text("d"), Some(said.as_str()));
        assert_eq!(said, "EJbuFSxoqLVVRwfobhgQkWhJVWzZaeUWgM4sseN8LyCZ");
    }
}
