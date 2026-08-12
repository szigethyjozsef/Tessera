# ADR-0001 — Tauri v2 with a Rust crypto core

**Status:** Accepted · **Date:** 2026-08-12

## Context

The application must run on Windows, Linux and Android from one codebase. The
developer's existing strengths are TypeScript, React and Node.js. Two properties are
non-negotiable for a password manager:

1. Key material must be zeroisable in memory.
2. Argon2id must run at realistic cost parameters without freezing the UI.

## Options considered

**React Native.** Familiar language, but no official Linux desktop target, and
JavaScript strings are immutable and garbage-collected — key material cannot be
reliably overwritten. Native modules would still be required for the cryptography,
so native compilation is not avoided, only made worse.

**Electron.** Same memory problem, no mobile support, large binaries.

**.NET / Avalonia.** Good desktop story, but `string` has the same immutability
problem and `SecureString` is deprecated and a no-op on Linux and macOS.

**Tauri v2 + Rust core.** Frontend stays React/TypeScript. The security-critical
core is Rust, where `zeroize` and `secrecy` make memory hygiene achievable. Tauri v2
targets desktop and mobile, and its v2 architecture was independently audited by
Radically Open Security.

## Decision

Tauri v2. React + TypeScript frontend, `vault-core` crate in Rust, communicating
over a deliberately narrow IPC surface of roughly a dozen commands.

## Consequences

- **Accepted cost:** learning Rust. Budgeted at 2–3 weeks, overlapping Phase 1,
  which *is* the crypto core — so the learning and the deliverable coincide.
- Tauri's mobile support is younger than its desktop support; some plugins are
  desktop-only. Verify plugin availability before depending on one.
- OS-level autofill and passkey provider registration require native Kotlin
  regardless of framework. Tauri v2 supports Kotlin plugins, so this is possible,
  but it is not free with any choice.
- The narrow IPC surface must be treated as a trust boundary and validated on the
  Rust side. The frontend is never assumed to be well-behaved.
