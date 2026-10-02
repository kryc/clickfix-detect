# Contributing

## Development environment

The workspace MSRV is Rust 1.85. Use Rust 1.85.1 with `rustfmt`, Clippy, and the
`wasm32-unknown-unknown` target:

```console
rustup toolchain install 1.85.1 --profile minimal --component rustfmt,clippy
rustup target add wasm32-unknown-unknown --toolchain 1.85.1
```

## Required checks

Run the smallest relevant test while developing, then run the complete checks
before submitting a pull request:

```console
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
cargo check --locked -p clickfix-wasm --target wasm32-unknown-unknown --release
cargo audit
```

Compile any affected fuzz package, for example:

```console
cargo check --locked --manifest-path binary-inspector/fuzz/Cargo.toml --bins
```

## Change guidelines

- Preserve hermetic behavior: never invoke native payloads or write analyzed
  data to the host filesystem or registry.
- Keep analysis bounded and return partial reports rather than silently
  discarding malformed or resource-limited evidence.
- Use typed process, network, file, artifact, and causal-provenance records.
- Add a regression for every detector false negative or parser crash.
- Keep source-attributed fixtures defanged and document whether they are
  complete, reconstructed, representative, or truncated.
- Update report-schema documentation when serialized fields change.

Security-sensitive reports should follow [SECURITY.md](SECURITY.md), not the
public issue tracker.
