# ADR-0004 — Sync over user-owned storage

**Status:** Accepted · **Date:** 2026-08-12

## Context

Users want their vault on more than one device. The product promise is that no
vendor server holds their data.

## Options considered

**Vendor-hosted sync.** Best user experience, but contradicts the core promise,
creates an ongoing hosting cost, and makes the project a target.

**LAN-only sync.** Strongest privacy story, zero infrastructure, but requires both
devices to be awake on the same network — in practice a phone and a laptop rarely are.

**User-owned remote storage.** WebDAV, Nextcloud, or a folder already synchronised by
Dropbox or Drive. Asynchronous, no simultaneity requirement, and the vendor holds
nothing because there is no vendor in the path.

## Decision

User-owned storage is the default and the free tier. Optional vendor-hosted sync may
later be offered as a paid convenience, using the identical encrypted format — so it
is genuinely a convenience and not a capability the free tier lacks.

## Consequences

- The storage target is untrusted by design; the threat model reflects this.
- Conflict resolution is unavoidable and must be built properly. See the format
  specification, §5.
- **Rollback is not detected in v1.** A malicious host can serve stale files. Backups
  are the user's responsibility and the application must make them one click.
- Setup is harder than "log in with email". A guided setup flow is required, and
  WebDAV configuration errors must produce comprehensible messages.
