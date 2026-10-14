// KERI messages start with a version string, the `v` field, such as `KERI10JSON0000fd_`:
//
// - `KERI`: the protocol (ACDC credentials use `ACDC`).
// - `10`: the protocol version, major 1, minor 0, one hexadecimal digit each.
// - `JSON`: how the message is serialized.
// - `0000fd`: the size of the whole serialized message in bytes, as six hexadecimal digits.
// - `_`: the terminator.
//
// The size lets a parser find where one message ends in a stream of messages without parsing
// JSON. Because a SAID's placeholder is as wide as the SAID, the size stays correct after the SAID
// is filled in.

use keri_cesr::crypto::digest::DigestAlgorithm;
use keri_protocol::said::Said;
use keri_protocol::serialization::{Sad, SerializedEvent};

/// Returns the message size recorded in a version string such as `KERI10JSON0000fd_`.
fn size_from_version(version: &str) -> Option<usize> {
    let digits = version.get(10..16)?;
    usize::from_str_radix(digits, 16).ok()
}

fn main() {
    // You can optionally experiment here.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_size() {
        assert_eq!(size_from_version("KERI10JSON0000fd_"), Some(253));
        assert_eq!(size_from_version("ACDC10JSON000197_"), Some(407));
        assert_eq!(size_from_version("KERI10"), None);
    }

    #[test]
    fn the_size_matches_the_serialized_message() {
        let mut sad = Sad::new();
        // The size is unknown until serialization, so it starts as zeros.
        sad.insert("v", "KERI10JSON000000_").unwrap();
        sad.insert("t", "rpy").unwrap();
        sad.insert("d", "").unwrap();
        sad.insert("r", "/hello").unwrap();

        let computed = Said::compute(&sad, DigestAlgorithm::Blake3_256, "d").unwrap();
        let message = SerializedEvent::from_sad(computed.sad().clone()).unwrap();
        let version = message.sad().get_text("v").unwrap();

        assert_eq!(size_from_version(version), Some(message.raw().len()));
    }
}
