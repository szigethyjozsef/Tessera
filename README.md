# Tessera

An offline-first, zero-knowledge password manager for desktop and mobile.

> ⚠️ **Early development — do not use for real credentials.**
> This project has not been audited by a third party. Until it has, treat it as a
> learning and portfolio project. See [SECURITY.md](SECURITY.md).

---

## What this is

Tessera stores credentials in an encrypted vault **on your device**. There is no
Tessera server, no Tessera account, and no telemetry. Synchronisation between
devices is optional and runs over storage **you already own** (WebDAV, Nextcloud,
a synced folder). The vault is encrypted before it ever touches that storage, so
the storage provider sees only opaque bytes.

## Design principles

1. **Offline by default.** Every core feature works with the network disabled.
2. **The vault never leaves the device in plaintext.** Encryption happens before I/O, always.
3. **No proprietary lock-in.** The vault format is documented and the core is open source.
4. **Honest about limits.** What the threat model does *not* cover is documented as
   carefully as what it does.

## Status

| Area | State |
| --- | --- |
| Vault format specification | Draft — see [docs/VAULT_FORMAT.md](docs/VAULT_FORMAT.md) |
| Crypto core (Rust) | Not started |
| Desktop UI | Not started |
| Android | Not started |
| Sync | Not started |

## Architecture

```
┌──────────────────────────────────────────┐
│  React + TypeScript                      │
│  UI, state, search, strength meter        │
└────────────────┬─────────────────────────┘
                 │ Tauri IPC (invoke)
┌────────────────▼─────────────────────────┐
│  vault-core (Rust)                       │
│  Argon2id · XChaCha20-Poly1305 · zeroize │
│  vault format · entry CRUD · TOTP        │
└──────────────────────────────────────────┘
```

The IPC boundary is deliberately narrow (roughly a dozen commands). Secrets are
returned across it only when the UI must display them, and never logged.

## Repository layout

```
.
├── src/                    React + TypeScript frontend
├── src-tauri/              Tauri shell (Rust)
│   └── src/
├── crates/
│   └── vault-core/         Crypto + vault logic. Apache-2.0.
├── docs/
│   ├── VAULT_FORMAT.md     On-disk format specification
│   ├── THREAT_MODEL.md     What is and is not defended against
│   └── adr/                Architecture Decision Records
├── SECURITY.md
└── README.md
```

## Licensing

Tessera is **open core**:

- `crates/vault-core/` — Apache-2.0. The cryptography and vault format are open so
  they can be reviewed, and so your data is never trapped in an unreadable file.
- Everything else — see [LICENSE](LICENSE).

## Roadmap

- [x] **Phase 0** — Specification, threat model, ADRs
- [x] **Phase 1** — Crypto core with test vectors
- [x] **Phase 2** — Vault layer: entries, versioning, tombstones, migrations
- [ ] **Phase 3** — Desktop UI, auto-lock, generator
- [ ] **Phase 4** — TOTP, password history
- [ ] **Phase 5** — Sync over user-owned storage
- [ ] **Phase 6** — Android
- [ ] **Phase 7** — Passkeys, browser extension

## Documentation

- [Vault format specification](docs/VAULT_FORMAT.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Architecture Decision Records](docs/adr/0000-index.md)
