# Changelog

## 0.2.3-candidate — 2026-10-25

- Added a read-only GitHub writer-authorization gate and 27 adversarial tests.
- Requires independent reviews, source protection, and separate state-only
  GitHub App repository scope before any writer could be approved.
- Live gate intentionally BLOCKED, no grant or secret installation.


## 0.2.2-candidate — 2026-10-25
- Identified REST `force:false` as fast-forward-only, not atomic expected-old
  commit compare-and-swap. Refactored gateway to GraphQL `updateRefs`
  `beforeOid` / `afterOid` request with fail-closed unknown outcomes.
- Added adversarial test cases for stale expected-head writes, missing GraphQL
  acknowledgement, and a timeout after a mutation possibly succeeded.
- Exercised real synthetic Git branch race without Actions write tokens.
- No backward compatibility with prior proof implementations.
- Remains an unmerged security-reviewed candidate only.

## 0.2.1-candidate — 2026-10-25
- Read-only gateway identity probe; simulated Git ref updates (57 E1 cases).

## 0.2.0-candidate — 2026-10-25
- Canonical pure deterministic H-00 model and tracked SHA256 manifest.
