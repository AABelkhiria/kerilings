# kerilings

Small exercises to learn [KERI](https://trustoverip.github.io/kswg-keri-specification/),
[CESR](https://trustoverip.github.io/kswg-cesr-specification/) and
[ACDC](https://trustoverip.github.io/kswg-acdc-specification/) by writing Rust, in the style of
[Rustlings](https://github.com/rust-lang/rustlings).

Each exercise is a short program with a `TODO`: a missing derivation code, a wrong threshold, a
signature over the wrong bytes. Fix it, save, and the exercise reruns and moves on when it compiles
and its tests pass. Once you solve an exercise, its solution appears in `solutions/` for comparison.

Everything runs offline, on the published crates:

| Crate | Used for |
|---|---|
| [`keri-cesr`](https://docs.rs/keri-cesr) | CESR primitives, keys, signatures, digests, salts |
| [`keri-protocol`](https://docs.rs/keri-protocol) | SAIDs, prefixes, key events, thresholds, attachments |
| [`keri-acdc`](https://docs.rs/keri-acdc) | Credentials, issuance and revocation, IPEX |

## Sections

| Directory | Topic |
|---|---|
| `00_intro` | How the exercises work |
| `01_cesr` | Derivation codes, text and binary encodings, streams, counters |
| `02_signatures` | Signing and verifying, transferable and non-transferable keys, indexed signatures |
| `03_keys` | Salts and key derivation, digests, pre-rotation commitments |
| `04_said` | Self-addressing identifiers |
| `05_inception` | Inception events and identifier prefixes, next-key commitments, thresholds |
| `06_rotation` | Rotation and interaction events |
| `07_attachments` | Signature groups and message streams |
| `08_credentials` | ACDC credentials and their SAIDs |
| `09_issuance` | Issuance, anchoring in the issuer's log, revocation |
| `10_ipex` | The IPEX exchange messages |

## Getting started

Install Rust (1.97 or newer), then kerilings:

```bash
cargo install --locked --git https://github.com/AABelkhiria/kerilings
```

Create the exercises and start:

```bash
kerilings init
cd kerilings
kerilings
```

The first exercise builds the cryptographic dependencies, which takes a minute; the rest rebuild
quickly. Enter `h` for a hint, `l` for the list of exercises, `q` to quit; run `kerilings` again in the
same directory to continue where you left off.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

kerilings is a fork of [Rustlings](https://github.com/rust-lang/rustlings) and is licensed under the
[MIT license](LICENSE).
