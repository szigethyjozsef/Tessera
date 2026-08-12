# Tessera Vault Format

**Specification version:** 1 (draft)
**Status:** Draft — breaking changes still allowed until the first tagged release.

This document is normative. If the implementation and this document disagree, the
document is correct and the implementation is a bug.

---

## 1. Goals

- A third party with full read access to the vault directory learns **nothing** about
  the stored secrets.
- Individual entries can be synchronised independently, so a change to one entry
  does not require re-uploading the whole vault.
- KDF parameters can be raised over time without breaking older vaults.
- The format is simple enough to write a recovery tool against in an afternoon.

## 2. Directory layout

```
my-vault/
├── vault.json            Manifest. Plaintext. Contains no secrets.
└── entries/
    ├── 018f2c3a-….json   One encrypted record per entry.
    ├── 018f2c41-….json
    └── …
```

There is deliberately **no index file**. An index would be rewritten on every change
and would become the single hottest source of sync conflicts. Listing entries means
decrypting every record; at a few thousand entries of a few hundred bytes each this
is measured in milliseconds. See [ADR-0003](adr/0003-per-entry-records.md).

## 3. Manifest — `vault.json`

Stored in plaintext. It must not contain anything that helps an attacker other than
the parameters required to *attempt* a key derivation.

```jsonc
{
  "magic": "TESSERA-VAULT",
  "formatVersion": 1,
  "vaultId": "018f2c3a-7b21-7c4e-9f10-2a5d8e6b1c33",
  "createdAt": "2026-08-12T09:14:00Z",

  "kdf": {
    "algorithm": "argon2id",
    "argonVersion": 19,
    "memoryKiB": 65536,
    "iterations": 3,
    "parallelism": 4,
    "salt": "<base64, 16 bytes>"
  },

  "wrappedDek": {
    "algorithm": "xchacha20poly1305",
    "nonce": "<base64, 24 bytes>",
    "ciphertext": "<base64, 32 bytes + 16 byte tag>"
  },

  "kdfUpgradedAt": null
}
```

### 3.1 Key hierarchy

```
master password + kdf.salt
        │
        ▼  Argon2id
       KEK  (32 bytes, never persisted)
        │
        ▼  unwraps
       DEK  (32 bytes, random, generated once at vault creation)
        │
        ▼  encrypts
    every entry record
```

The DEK is generated once with a CSPRNG and never changes for the lifetime of the
vault. Changing the master password re-derives the KEK and rewrites `wrappedDek`
only — entry records are untouched. This makes a password change an O(1) operation
instead of O(n), and it is what later makes multi-device key sharing possible.

### 3.2 Verifying the master password

There is **no** password hash anywhere in the format. Verification is:

1. Derive the KEK from the supplied password.
2. Attempt to decrypt `wrappedDek`.
3. If the Poly1305 authentication tag validates, the password was correct.

An attacker with the vault file must run Argon2id per guess. There is nothing
cheaper to attack.

### 3.3 Raising KDF parameters

On unlock, if `kdf` is weaker than the current recommended baseline, the application
offers to upgrade. The upgrade re-derives a new KEK with the new parameters, rewrites
`wrappedDek`, sets `kdfUpgradedAt`, and does not touch entries. Old vaults must
always remain openable using the parameters recorded in their own manifest.

## 4. Entry records — `entries/<uuid>.json`

Filenames are UUIDv7. UUIDv7 embeds a creation timestamp; this is accepted (see §7).

```jsonc
{
  "id": "018f2c41-b902-7d18-8e44-6c9a01ff3ba7",
  "formatVersion": 1,
  "nonce": "<base64, 24 bytes>",
  "ciphertext": "<base64>"
}
```

### 4.1 AEAD parameters

- **Cipher:** XChaCha20-Poly1305.
- **Nonce:** 24 bytes from a CSPRNG, freshly generated on **every** write. A 192-bit
  random nonce makes collision probability negligible without a counter.
- **Associated data (AAD):** the UTF-8 concatenation
  `"<vaultId>|<id>|<formatVersion>"`.

The AAD binds each ciphertext to its own entry ID and to its vault. Without it, an
attacker with write access to the storage could swap two record files and silently
make the user log into the wrong account with the wrong credential — the ciphertexts
would still authenticate.

### 4.2 Decrypted payload

```jsonc
{
  "id": "018f2c41-b902-7d18-8e44-6c9a01ff3ba7",
  "type": "login",
  "version": 7,
  "createdAt": "2026-08-12T09:20:11Z",
  "updatedAt": "2026-08-19T18:03:44Z",
  "deletedAt": null,
  "lastModifiedBy": "device:018f2c3f-…",

  "fields": {
    "title":    { "value": "GitHub",           "updatedAt": "2026-08-12T09:20:11Z" },
    "username": { "value": "szigethyjoco",     "updatedAt": "2026-08-12T09:20:11Z" },
    "password": { "value": "…",                "updatedAt": "2026-08-19T18:03:44Z" },
    "url":      { "value": "https://github.com", "updatedAt": "2026-08-12T09:20:11Z" },
    "notes":    { "value": "",                 "updatedAt": "2026-08-12T09:20:11Z" }
  },

  "totp": {
    "secret": "<base32>",
    "algorithm": "SHA1",
    "digits": 6,
    "period": 30
  },

  "history": [
    { "field": "password", "value": "…", "replacedAt": "2026-08-19T18:03:44Z" }
  ],

  "tags": ["work"],
  "favorite": false
}
```

**`type`** is one of `login`, `note`, `card`, `identity`, `totp`, `passkey`.
Unknown types must be preserved verbatim on write, so that a newer client's entries
survive a round trip through an older client.

**`version`** is a monotonic counter incremented on every write. It is the primary
input to conflict detection.

**Per-field `updatedAt`** allows a merge to keep the newer username and the newer
password even when they were changed on different devices.

**`history`** is capped (default 10 entries, user-configurable, user-clearable).
Old passwords are live credentials elsewhere and are treated as secrets.

### 4.3 Deletion

Deletion is a **tombstone**, never a file removal. The record is rewritten with:

- `deletedAt` set,
- `version` incremented,
- `fields`, `totp` and `history` emptied.

A hard delete would be undone by the next sync from a device that had not yet seen
it. Tombstones are purged only after a retention period (default 90 days) and only
once every known device has acknowledged them.

## 5. Conflict resolution

On sync, for each record present in both locations:

| Condition | Action |
| --- | --- |
| Local `version` == remote `version` | No change |
| One side's `version` is strictly greater and its history contains the other's | Fast-forward |
| Both changed since the last common version | **Conflict** |

On conflict, merge per field by `updatedAt`. Where two devices changed the *same*
field, do **not** guess: surface both values to the user and let them choose. A
silently discarded password is a lost account.

Deletion always wins over modification within the same sync round; the user is
notified.

## 6. Migrations

`formatVersion` appears in both the manifest and every record. On unlock:

1. If `formatVersion` is greater than the client supports → refuse to open,
   explain that the app must be updated. **Never** attempt a partial read.
2. If lower → copy the entire vault directory to `my-vault.backup-v<n>-<date>/`,
   then migrate forward one version at a time.
3. Migration steps are pure functions `vN → vN+1` and each has its own test fixture
   committed under `crates/vault-core/tests/fixtures/`.

## 7. Metadata that is *not* protected

Stated plainly, because pretending otherwise would be dishonest:

- **Number of entries** — visible from the file count.
- **Approximate creation time of each entry** — UUIDv7 encodes a timestamp.
- **Modification activity** — filesystem mtimes reveal when you changed what, and
  a cloud provider hosting the sync target sees this too.
- **Approximate entry size** — ciphertext length is not padded.

Mitigations deferred to a later format version: padding records to fixed size
buckets, and using random UUIDv4 filenames. Both are cheap to add and should be
reconsidered before the first stable release.

## 8. Cryptographic dependencies

| Purpose | Choice |
| --- | --- |
| KDF | Argon2id, m=64 MiB, t=3, p=4 |
| AEAD | XChaCha20-Poly1305 |
| RNG | OS CSPRNG (`getrandom`) |
| Key zeroisation | `zeroize` on every type holding key material |

No custom cryptographic primitives are implemented in this project. Ever.
