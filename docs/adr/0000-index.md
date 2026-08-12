# Architecture Decision Records

Each ADR records one decision, the context that forced it, and the consequences we
accepted. ADRs are immutable once accepted: if a decision changes, write a new ADR
that supersedes the old one rather than editing history.

Format: [MADR](https://adr.github.io/madr/), lightly adapted.

| # | Title | Status |
| --- | --- | --- |
| [0001](0001-tauri-rust-core.md) | Tauri v2 with a Rust crypto core | Accepted |
| [0002](0002-crypto-primitives.md) | Argon2id + XChaCha20-Poly1305, DEK/KEK hierarchy | Accepted |
| [0003](0003-per-entry-records.md) | One encrypted file per entry | Accepted |
| [0004](0004-user-owned-sync.md) | Sync over user-owned storage | Accepted |
| [0005](0005-open-core-licensing.md) | Open core licensing | Accepted |
