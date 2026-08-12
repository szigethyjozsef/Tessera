# Security Policy

## Project maturity

**Tessera has not been independently audited and is in early development.**

Do not use it to store credentials you cannot afford to lose or to have exposed.
This warning stays here until a third party has reviewed the cryptographic core.
It is not boilerplate modesty — an unaudited password manager written by one
developer deserves exactly this much scepticism, and saying so is part of taking
the problem seriously.

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Use GitHub's private vulnerability reporting (Security → Report a vulnerability),
or email `szigethyjoco@gmail.com`.

Include what you did, what happened, what you expected, and the affected version or
commit. A proof of concept helps but is not required.

**Response targets:** acknowledgement within 5 days, an initial assessment within
14 days. This is a spare-time project and those are honest targets, not an SLA.

## Disclosure

Coordinated disclosure. Report privately, we agree on a timeline, the fix ships,
then details are published. Reporters are credited unless they prefer otherwise.

## Scope

**In scope:** the cryptographic core, the vault format, key handling, memory
hygiene, sync integrity, auto-lock bypasses, and anything that exposes plaintext
secrets outside their intended lifetime.

**Out of scope:** issues requiring a compromised operating system or root access,
cold boot and DMA attacks, and social engineering of users. These are documented as
out of scope in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) — but if you believe
something there is misclassified, that itself is a valuable report.
