# Threat Model

**Status:** Draft, Phase 0.
Revisit at the end of every phase. A threat model written once and never reopened
is decoration.

---

## Assets

| Asset | Why it matters |
| --- | --- |
| Master password | Compromise means total compromise. |
| Data Encryption Key (DEK) | Decrypts every entry. Exists only in memory while unlocked. |
| Entry secrets | Passwords, TOTP seeds, passkey private keys, card numbers. |
| Entry metadata | Titles and URLs alone reveal which services a user holds accounts with. |

## Assumptions

1. The operating system and hardware are not compromised while the vault is unlocked.
2. The user's master password has meaningful entropy. The application measures and
   warns, but cannot enforce.
3. Underlying primitives (Argon2id, XChaCha20-Poly1305) are sound.
4. Sync storage is **untrusted**: assume the provider reads every byte and may
   attempt to modify or roll back files.

---

## In scope

### T1 — Stolen or lost device
An attacker has the device and the vault files, but not the master password.

*Defence:* Argon2id with a high memory cost makes offline guessing expensive.
There is no password hash to attack independently of the ciphertext. Entries are
only ever written encrypted.

*Residual risk:* A weak master password. Nothing in the design fixes this.

### T2 — Malicious or breached sync provider
The storage host reads, tampers with, or rolls back vault files.

*Defence:* All secrets are encrypted before upload. AEAD authentication tags detect
tampering; the AAD binding (see the format spec, §4.1) detects record swapping.

*Residual risk:* **Rollback and denial of service are not defended against.** A
provider can serve an old copy or delete the vault. Users must keep their own
backups. Rollback detection is deferred to a later version.

### T3 — Local unprivileged process reading the vault directory
Malware without root, scraping user files.

*Defence:* The vault at rest is useless without the master password.

### T4 — Shoulder surfing and screen capture
*Defence:* Secrets masked by default. `FLAG_SECURE` on Android; on desktop, window
capture exclusion where the platform provides it.

*Residual risk:* **iOS provides no API to block screenshots.** Only detection after
the fact is possible. Documented, not solved.

### T5 — Clipboard leakage
*Defence:* Autofill is preferred and the clipboard is a fallback. When used, the
clipboard is cleared after a timeout and marked sensitive
(`EXTRA_IS_SENSITIVE` on Android, `CF_CLIPBOARD_VIEWER_IGNORE` on Windows).

*Residual risk:* **Substantial.** Third-party clipboard managers and OS clipboard
history may retain the value regardless. The clipboard is not a trustworthy channel
and the UI says so.

### T6 — Key material reaching disk
Swap files, hibernation images and core dumps can persist a key for months.

*Defence:* `mlock` / `VirtualLock` on pages holding key material; core dumps
disabled for the process; `zeroize` on drop for all key-bearing types.

### T7 — Phishing
*Defence:* Autofill matches on exact origin and refuses to fill on a mismatch.
Punycode and homograph domains are flagged. Passkeys are origin-bound by the
WebAuthn protocol and cannot be phished at all.

### T8 — Unattended unlocked vault
*Defence:* Auto-lock on idle timeout, backgrounding, screen lock and system sleep.
Locking **zeroises the DEK in memory**; it is not a UI overlay.

---

## Out of scope

These are stated explicitly so that no marketing copy ever implies otherwise.

- **Compromised operating system.** Root access, a kernel-level keylogger or a
  malicious OS defeats every measure here. No userspace application can survive this.
- **Cold boot and DMA attacks.** Physical access to a running, unlocked device.
- **Hardware side channels.** Spectre-class attacks, EM emissions.
- **Rubber-hose / legal compulsion.** There is no duress vault or plausible
  deniability feature. If one is added later it will be modelled separately —
  such features are notoriously easy to get wrong.
- **Supply chain.** Dependency integrity is managed with lockfiles, `cargo audit`
  and reproducible builds where practical, but this is mitigation, not a solution.
- **Availability.** The project defends confidentiality and integrity. It does not
  guarantee that a user can always reach their data. Backups are the user's
  responsibility and the application must make them easy.

---

## Known weaknesses in the current design

| Issue | Severity | Plan |
| --- | --- | --- |
| No rollback detection on sync | Medium | Signed monotonic counter, post-MVP |
| Entry count and timing metadata visible | Low–Medium | Size padding + UUIDv4 filenames, before v1.0 |
| No third-party audit | High | Open source core; seek review before recommending real-world use |
| Emergency access relies on a printed recovery kit | Low | Shamir's Secret Sharing as an advanced option |

---

## Review log

| Date | Phase | Change |
| --- | --- | --- |
| 2026-08-12 | 0 | Initial draft |
