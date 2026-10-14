// A KERIA agent keeps a Signify client's salts for it, but must never be able to read them.
// The client seals each salt to its own public key (an X25519 sealed box, derived from its
// Ed25519 key) before handing it over; only the matching private key can open it.
//
// `Encrypter` seals to a public key; `Decrypter` opens with the private key of a signer. Each
// seal uses fresh randomness, so the ciphertext (code `1AAH` for a salt) differs every time.

use keri_cesr::crypto::cipher::{Ciphertext, Decrypter, Encrypter};
use keri_cesr::crypto::salt::{Salt, SecurityTier};
use keri_cesr::crypto::signer::Signer;
use keri_cesr::crypto::verifier::VerificationKey;

/// Seals `salt` so only the holder of `recipient`'s private key can open it.
fn seal(salt: &Salt, recipient: &VerificationKey) -> Ciphertext {
    Encrypter::from_verification_key(recipient)
        .unwrap()
        .encrypt_salt(salt)
        .unwrap()
}

/// Opens a sealed salt with `owner`'s private key.
fn open(sealed: &Ciphertext, owner: &Signer) -> Option<Salt> {
    // TODO: Build a decrypter from `owner` and decrypt the salt (use `SecurityTier::Low`).
    todo!()
}

fn main() {
    // You can optionally experiment here.
}

#[cfg(test)]
mod tests {
    use super::*;
    use keri_cesr::crypto::verifier::KeyTransferability;

    const SALT: &str = "0ABeuT2dErMrqFE5Dmrnc2Bq";

    fn signer(seed: u8) -> Signer {
        Signer::from_seed(&[seed; 32], KeyTransferability::Transferable).unwrap()
    }

    #[test]
    fn owner_opens_it() {
        let client = signer(7);
        let salt = Salt::from_qb64(SALT, SecurityTier::Low).unwrap();
        let sealed = seal(&salt, client.verifier());
        assert!(sealed.qb64().unwrap().starts_with("1AAH"));

        let opened = open(&sealed, &client).unwrap();
        assert_eq!(opened.expose_qb64().unwrap().as_str(), SALT);
    }

    #[test]
    fn the_agent_cannot() {
        let salt = Salt::from_qb64(SALT, SecurityTier::Low).unwrap();
        let sealed = seal(&salt, signer(7).verifier());
        assert!(open(&sealed, &signer(9)).is_none());
    }

    #[test]
    fn every_seal_differs() {
        let salt = Salt::from_qb64(SALT, SecurityTier::Low).unwrap();
        let client = signer(7);
        assert!(seal(&salt, client.verifier()) != seal(&salt, client.verifier()));
    }
}
