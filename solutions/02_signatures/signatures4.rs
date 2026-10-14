// An identifier can have several signing keys. Its key event lists them in order, and each
// signature on an event says which key made it with an index. These are indexed signatures.
//
// In qb64 an indexed Ed25519 signature starts with `A` and then the index in Base64: `AA` is the
// key at index 0, `AB` at index 1. The signatures follow a `-A` counter, so the attachment for
// two controller signatures is `-AAC` + the first + the second.
//
// `SignaturePlacement::both_lists(i)` places a signature at index `i` of the current key list
// (and of the prior next-key list, which matters for rotations).

use keri_cesr::counter::{Counter, CounterCode};
use keri_cesr::crypto::signer::{SignaturePlacement, Signer};

/// The attachment of controller signatures on `message`: each signer signs at its own index.
fn attach_signatures(signers: &[Signer], message: &[u8]) -> String {
    let count = u32::try_from(signers.len()).unwrap();
    let mut attachment = Counter::new(CounterCode::CONTROLLER_INDEXED_SIGNATURES, count)
        .unwrap()
        .qb64()
        .unwrap();
    for (index, signer) in signers.iter().enumerate() {
        let index = u32::try_from(index).unwrap();
        let signature = signer
            .sign_indexed(message, SignaturePlacement::both_lists(index))
            .unwrap();
        attachment.push_str(&signature.qb64().unwrap());
    }
    attachment
}

fn main() {
    // You can optionally experiment here.
}

#[cfg(test)]
mod tests {
    use super::*;
    use keri_cesr::crypto::signature::IndexedSignature;
    use keri_cesr::crypto::verifier::KeyTransferability;

    #[test]
    fn two_keys() {
        let signers = [
            Signer::from_seed(&[7_u8; 32], KeyTransferability::Transferable).unwrap(),
            Signer::from_seed(&[8_u8; 32], KeyTransferability::Transferable).unwrap(),
        ];
        let attachment = attach_signatures(&signers, b"hello world");

        assert!(attachment.starts_with("-AAC"));
        let first = IndexedSignature::from_qb64(&attachment[4..92]).unwrap();
        let second = IndexedSignature::from_qb64(&attachment[92..]).unwrap();
        assert_eq!(first.index(), 0);
        assert_eq!(second.index(), 1);
        assert!(attachment[92..].starts_with("AB"));

        signers[1]
            .verifier()
            .verify(second.raw(), b"hello world")
            .unwrap();
    }
}
