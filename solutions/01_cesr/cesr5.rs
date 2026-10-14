// Primitives of the same kind travel in groups, introduced by a count code. A counter starts
// with `-`, then a code for the group's kind, then the number of members in Base64.
//
// `-A` introduces the controller's indexed signatures on a key event: `-AAC` means "two
// controller signatures follow". A parser reads the counter, then exactly that many signatures.

use keri_cesr::counter::{Counter, CounterCode};

/// The counter that introduces `count` controller indexed signatures.
fn controller_signatures(count: u32) -> Counter {
    Counter::new(CounterCode::CONTROLLER_INDEXED_SIGNATURES, count).unwrap()
}

fn main() {
    // You can optionally experiment here.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_signatures() {
        assert_eq!(controller_signatures(2).qb64().unwrap(), "-AAC");
    }

    #[test]
    fn count_is_base64() {
        // 64 is `BA` in Base64: B = 1, A = 0.
        assert_eq!(controller_signatures(64).qb64().unwrap(), "-ABA");
    }

    #[test]
    fn parses_back() {
        let counter = Counter::from_qb64("-AAD").unwrap();
        assert!(counter.code() == CounterCode::CONTROLLER_INDEXED_SIGNATURES);
        assert_eq!(counter.count(), 3);
    }
}
