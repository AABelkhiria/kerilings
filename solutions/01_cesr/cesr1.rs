// Every CESR primitive starts with a derivation code. The code is the "hard" part: one, two or
// four characters that name what follows. From the code alone a parser knows the full size of
// the primitive, so primitives can be concatenated with no separators.
//
// In text (qb64), every 3 bytes of raw material become 4 Base64 characters. A 32-byte Ed25519
// key needs 43 characters plus padding; the 1-character code takes the padding's place, so the
// whole primitive is 44 characters.
//
// Work out the sizes the code tables give for a few common codes.

use keri_cesr::code::DerivationCode;

/// How many qb64 characters an Ed25519 public key (`D`) takes.
fn ed25519_key_length() -> usize {
    44
}

/// How many characters the code of an Ed25519 signature (`0B`) takes.
fn signature_code_length() -> usize {
    2
}

/// How many qb64 characters an Ed25519 signature takes in all.
fn signature_length() -> usize {
    88
}

fn main() {
    // You can optionally experiment here.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_public_key() {
        let size = DerivationCode::ED25519.size();
        assert_eq!(DerivationCode::ED25519.as_str(), "D");
        assert_eq!(size.hard_size(), 1);
        assert_eq!(size.raw_size(), Some(32));
        assert_eq!(size.full_size(), Some(ed25519_key_length()));
    }

    #[test]
    fn ed25519_signature() {
        let size = DerivationCode::ED25519_SIGNATURE.size();
        assert_eq!(DerivationCode::ED25519_SIGNATURE.as_str(), "0B");
        assert_eq!(size.hard_size(), signature_code_length());
        assert_eq!(size.full_size(), Some(signature_length()));
    }
}
