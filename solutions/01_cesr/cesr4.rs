// Because every code fixes its primitive's size, CESR needs no delimiters: a parser reads the
// code at the front of the stream, takes exactly that many characters, and continues with the
// rest.
//
// `QualifiedMaterial::parse_qb64` parses the first primitive of its input and reports how many
// characters it consumed.

use keri_cesr::matter::QualifiedMaterial;

/// Splits a stream of concatenated primitives into their qb64 texts.
fn split(stream: &str) -> Vec<String> {
    let mut rest = stream;
    let mut primitives = Vec::new();
    while !rest.is_empty() {
        let parsed = QualifiedMaterial::parse_qb64(rest).unwrap();
        primitives.push(parsed.material().qb64().unwrap());
        rest = &rest[parsed.consumed()..];
    }
    primitives
}

fn main() {
    // You can optionally experiment here.
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "DAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g";
    const DIGEST: &str = "ENdJge-nCgyIC42MGYXQddvL9nm5ml-ZFOWq-WuDGp4k";
    const SIGNATURE: &str =
        "0BAeXqSxz_9YXhrkI5ECzTBHjQgdFbFDdOur5S_4l1ersaMubaJ79ihGrSFefF8foGQvdxX4ie4b8Z6Bxqm-w-AJ";

    #[test]
    fn splits_without_delimiters() {
        let stream = format!("{KEY}{SIGNATURE}{DIGEST}");
        assert_eq!(split(&stream), [KEY, SIGNATURE, DIGEST]);
    }

    #[test]
    fn empty_stream() {
        assert!(split("").is_empty());
    }
}
