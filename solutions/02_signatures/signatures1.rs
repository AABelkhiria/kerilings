// A signer holds a private Ed25519 key. It signs the exact bytes of a message, and anyone with
// the matching public key (the verifier) can check the signature.
//
// `Signer::from_seed` builds a signer from a 32-byte seed. Real keys come from a random source
// or a salt; a fixed seed keeps this exercise reproducible. The signer never exposes its seed,
// only its public `verifier()`.

use keri_cesr::crypto::CryptoError;
use keri_cesr::crypto::signature::UnindexedSignature;
use keri_cesr::crypto::signer::Signer;

/// Checks `signature` over `message` with the public key of `signer`.
fn check(
    signer: &Signer,
    signature: &UnindexedSignature,
    message: &[u8],
) -> Result<(), CryptoError> {
    signer.verifier().verify(signature.raw(), message)
}

fn main() {
    // You can optionally experiment here.
}

#[cfg(test)]
mod tests {
    use super::*;
    use keri_cesr::crypto::verifier::KeyTransferability;

    #[test]
    fn sign_and_verify() {
        let signer = Signer::from_seed(&[7_u8; 32], KeyTransferability::Transferable).unwrap();
        let message = b"hello world";

        let signature = signer.sign_unindexed(message).unwrap();
        assert_eq!(
            signature.qb64().unwrap(),
            "0BAeXqSxz_9YXhrkI5ECzTBHjQgdFbFDdOur5S_4l1ersaMubaJ79ihGrSFefF8foGQvdxX4ie4b8Z6Bxqm-w-AJ"
        );

        assert!(check(&signer, &signature, message).is_ok());
    }
}
