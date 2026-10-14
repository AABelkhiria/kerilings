// Signify does not store private keys. It stores a 128-bit salt (qb64 code `0A`) and derives
// every key from it with Argon2id and a path. The same salt and path always give the same key,
// so a client can recreate its keys from the salt alone; a different path gives an unrelated key.
//
// Signify's own client identity uses the paths `signify:controller00` for its current key and
// `signify:controller01` for its next one.

use keri_cesr::crypto::salt::{Salt, SecurityTier};
use keri_cesr::crypto::signer::Signer;
use keri_cesr::crypto::verifier::KeyTransferability;

const SALT: &str = "0ABeuT2dErMrqFE5Dmrnc2Bq";

/// The transferable signer at `path` under the salt.
fn derive(path: &str) -> Signer {
    let salt = Salt::from_qb64(SALT, SecurityTier::Low).unwrap();
    salt.derive_signer(path, KeyTransferability::Transferable)
        .unwrap()
}

fn main() {
    // You can optionally experiment here.
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public_key(path: &str) -> String {
        derive(path).verifier().qb64().unwrap()
    }

    #[test]
    fn current_key() {
        assert_eq!(
            public_key("signify:controller00"),
            "DOOhweA780NODlc4JQj02_ltW-1Sb-GHH2Ggo_Ib1mEU"
        );
    }

    #[test]
    fn next_key() {
        assert_eq!(
            public_key("signify:controller01"),
            "DK4EmW6jcFeuJPADoXtA-BcgBoDMpkQaMA9Uywd4z6E2"
        );
    }

    #[test]
    fn same_path_same_key() {
        assert_eq!(public_key("any/path"), public_key("any/path"));
    }
}
