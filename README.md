# Cowchat shared crates

Public cryptography, message types and transport client for Cowchat. Builds require no private repositories or Git credentials.

```sh
cargo test --locked --workspace --all-targets
```

Private Cowboy member authentication and room-key acquisition live in `cowchat-member` in core. The client accepts session proofs and caches zeroizing per-epoch keys; it does not resolve private protocol packages.

History extracted from cowboy-protocol at 3e115e23b9fc69e448343133879baf517c3d2ec6, restricted to the shared crates and their fixtures. Private member implementation paths are removed throughout the extracted history.
