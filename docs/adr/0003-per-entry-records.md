# ADR-0003 — One encrypted file per entry

**Status:** Accepted · **Date:** 2026-08-12

## Context

The vault can be stored as a single encrypted blob (KeePass-style) or as many small
encrypted records. Sync runs over user-owned file storage that offers no merge
semantics of its own.

## Decision

One encrypted file per entry, named by UUIDv7, plus a plaintext manifest. No index
file.

## Rationale

With a single blob, any change rewrites the entire vault. Two devices editing
different entries offline produce a whole-file conflict, and the only recovery is
"pick one file and lose the other's work". With per-entry records, those edits touch
different files and merge cleanly.

An index file was rejected: it would be rewritten on every change and would become
the single hottest conflict source, reintroducing the problem we are avoiding.
Listing means decrypting every record, which at realistic vault sizes is a few
milliseconds.

## Consequences

- **Accepted cost:** entry count, per-entry timestamps and approximate entry sizes
  leak to anyone who can list the directory. Documented in the threat model;
  mitigations (size padding, UUIDv4 filenames) deferred but planned before v1.0.
- Atomicity is now the application's problem. Every write is
  write-to-temp → fsync → atomic rename. A crash must never leave a half-written record.
- Deletion must be a tombstone. A removed file would be resurrected by the next sync
  from a device that had not seen the deletion.
