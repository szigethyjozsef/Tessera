# ADR-0005 — Open core licensing

**Status:** Accepted · **Date:** 2026-08-12

## Context

Nobody should trust an unaudited, closed-source password manager from an unknown
developer — and they would be right not to. The project also intends to generate
revenue eventually.

## Decision

`crates/vault-core` — the cryptography and vault format — is released under
Apache-2.0. The application shell, UI and any paid features remain under a separate
licence.

Apache-2.0 rather than MIT for the core, because it includes an explicit patent
grant, which matters more in cryptographic code.

## Consequences

- Independent review of the security-critical code becomes possible. Until a real
  audit happens, this is the closest available substitute and must not be described
  as equivalent to one.
- Users are guaranteed their data is never trapped: the format is public and a
  recovery tool can always be written.
- **This is effectively irreversible.** Code published under Apache-2.0 cannot be
  un-published. Anything that must stay proprietary must never be committed to that
  crate — decide placement *before* writing a file, not afterwards.
- Competitors may reuse the core. Accepted: the defensible value is in the product
  and its trustworthiness, not in a thousand lines of key wrapping.
