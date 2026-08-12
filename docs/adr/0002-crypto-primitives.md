# ADR-0002 — Argon2id + XChaCha20-Poly1305 with a DEK/KEK hierarchy

**Status:** Accepted · **Date:** 2026-08-12

## Context

The vault must resist offline brute force against a stolen file, and must detect
tampering by an untrusted sync host.

## Decision

**KDF:** Argon2id, m=64 MiB, t=3, p=4. Memory-hard, so GPU and ASIC attacks gain far
less than against PBKDF2. Parameters are stored in the manifest so they can be
raised later without breaking existing vaults.

**AEAD:** XChaCha20-Poly1305. The 192-bit nonce permits random nonce generation with
negligible collision risk, removing the need for nonce-counter bookkeeping across
devices — a state-synchronisation problem we would otherwise have to solve correctly
in a distributed setting. Authentication is built in, so tampering is detected.

**Key hierarchy:** the master password derives a KEK, which wraps a randomly
generated DEK, which encrypts entries.

## Consequences

- Master password changes rewrite only the wrapped DEK — O(1), not O(n).
- Multi-device key sharing later becomes possible without redesigning the format.
- Argon2id at 64 MiB is noticeable on low-end Android devices. Measure on real
  hardware in Phase 6; if unacceptable, lower `parallelism` before lowering `memory`.
- Password verification is "try to unwrap the DEK". No password hash exists, so
  there is nothing cheaper for an attacker to target.
- **No primitive is implemented by hand.** Vetted crates only (`argon2`,
  `chacha20poly1305` from RustCrypto).
