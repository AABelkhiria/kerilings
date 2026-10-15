# Contributing to kerilings

## Issues

You can open an issue [here](https://github.com/AABelkhiria/kerilings/issues/new).
If you're reporting a bug, please include the output of the following commands:

- `cargo --version`
- `kerilings --version`
- `ls -la`
- Your OS name and version

## Pull Requests

Unless it is small, please open an issue to discuss your idea first.

When updating an exercise, check if its solution needs to be updated.

## Adding An Exercise

- Name the file `exercises/NN_topic/topicN.rs`.
- Link the relevant crate docs and specification sections in `exercises/NN_topic/README.md`.
- Put the code the learner changes in normal functions, with a `// TODO: …` comment where changes are
  required. The tests only call those functions and assert.
- Add a solution at `solutions/NN_topic/topicN.rs`: the exercise with the `TODO` resolved.
- Add the [metadata for your exercise](#exercise-metadata) in the `kerilings-macros/info.toml` file.
- Run `cargo dev update` to update the `bin` list in `dev/Cargo.toml`.
- Run `cargo dev check --require-solutions`: every exercise must fail before its fix, every solution must
  pass, and solutions must be formatted.
- Make sure your exercise runs with `cargo run -- run topicN`.

### Exercise Metadata

```toml
[[exercises]]
name = "topicN"
dir = "NN_topic"
hint = """
A useful (multi-line) hint for your exercise.
Name the API to use without giving the full answer."""
```

If your exercise doesn't contain any test, add `test = false` to the exercise metadata.
But adding tests is recommended.

## Upstream

kerilings is a fork of [Rustlings](https://github.com/rust-lang/rustlings). The `upstream` remote points
to it; merge its releases to pick up fixes to the CLI.

## Releasing

1. Bump `version` in the root `Cargo.toml` (`[workspace.package]` and the `=` pin on `kerilings-macros`),
   and run `cargo check` to update `Cargo.lock`.
2. Add a `## [x.y.z] - YYYY-MM-DD` section to `CHANGELOG.md`.
3. Push to `main` and wait for the Check workflow to pass.
4. Run the Release workflow from the Actions tab. It publishes `kerilings-macros` then `kerilings` to
   crates.io, tags `vx.y.z` and creates the GitHub release from the changelog section.

The Release workflow needs a `crates-io` environment with a `CARGO_REGISTRY_TOKEN` secret.
