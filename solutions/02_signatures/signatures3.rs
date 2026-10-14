// The same Ed25519 public key gets one of two codes:
//
// - `D`, transferable: the key can be rotated. An identifier built on it has a key event log,
//   and control can move to new keys.
// - `B`, non-transferable: the key is the identifier, forever. It can never be rotated. KERI
//   uses these "basic" identifiers for witnesses and for ephemeral identities.
//
// The raw key bytes are identical; only the code (and so the promise) differs.

use keri_cesr::crypto::signer::Signer;
use keri_cesr::crypto::verifier::KeyTransferability;

/// The identifier a witness signs its receipts with: it will never rotate its key.
fn witness_key(seed: &[u8; 32]) -> String {
    let signer = Signer::from_seed(seed, KeyTransferability::NonTransferable).unwrap();
    signer.verifier().qb64().unwrap()
}

fn main() {
    // You can optionally experiment here.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn witness_is_non_transferable() {
        assert_eq!(
            witness_key(&[7_u8; 32]),
            "BOpKbGPinFIKvvVQexMuxfmVR3auvr57kkIe6mkURtIs"
        );
    }

    #[test]
    fn same_key_bytes_either_way() {
        let controller = Signer::from_seed(&[7_u8; 32], KeyTransferability::Transferable).unwrap();
        let controller = controller.verifier().qb64().unwrap();
        assert_eq!(controller, "DOpKbGPinFIKvvVQexMuxfmVR3auvr57kkIe6mkURtIs");
        assert_eq!(controller[1..], witness_key(&[7_u8; 32])[1..]);
    }
}
