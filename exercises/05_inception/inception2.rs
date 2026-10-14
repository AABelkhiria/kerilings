// Pre-rotation is KERI's answer to key compromise. An inception event names its current signing
// keys (`k`) and commits to the *next* ones (`n`) without revealing them: `n` holds digests of the
// next public keys. Only someone holding the next keys can later rotate to them, so an attacker
// who steals the current keys still cannot take over the identifier.
//
// The commitment to a key is the Blake3-256 digest of the key's qb64 text.

use keri_cesr::crypto::digest::{Digest, DigestAlgorithm};
use keri_cesr::crypto::signer::Signer;
use keri_cesr::crypto::verifier::{KeyTransferability, VerificationKey};
use keri_protocol::event::inception::InceptionBuilder;

/// Returns the pre-rotation commitment to `key`.
fn commitment(key: &VerificationKey) -> Digest {
    // TODO: Return the Blake3-256 digest of the key's qb64 text.
    todo!()
}

fn main() {
    // You can optionally experiment here.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commits_to_the_next_key() {
        let current = Signer::from_seed(&[1_u8; 32], KeyTransferability::Transferable).unwrap();
        let next = Signer::from_seed(&[2_u8; 32], KeyTransferability::Transferable).unwrap();

        let event = InceptionBuilder::new(vec![current.verifier().clone()])
            .next_key_digests(vec![commitment(next.verifier())])
            .build()
            .unwrap();

        let digests = event.serialized().next_key_digests().unwrap();
        assert_eq!(digests.len(), 1);
        assert_eq!(
            digests[0].qb64().unwrap(),
            "EHQEteSlbY8drT6QN0MNFGqlQlvWeCrI1evK9L7T0akI"
        );
        // The next key itself appears nowhere in the event.
        let raw = String::from_utf8(event.raw().to_vec()).unwrap();
        assert!(!raw.contains(&next.verifier().qb64().unwrap()));
    }
}
