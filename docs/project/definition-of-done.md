# Definition of Done — public C-05 test only

- [ ] Protected public `main` verified server-side, with CI required.
- [ ] Full immutable source SHA explicitly approved in repository variable.
- [ ] Real W-01 model call PASS with read-only repository permissions.
- [ ] Tokenless E1 PASS, including deliberate failure detection.
- [ ] Distinct fresh J-01 model reviewer PASS, including rejection control.
- [ ] Tokenless stage/preflight PASS with exact hash-bound synthetic evidence.
- [ ] Trusted publisher created exactly one DRAFT PR, with exactly two authorized changed files.
- [ ] Duplicate dispatch for the same SHA reuses the verified PR without writing duplicates.
- [ ] Tampering/invalid scopes/unauthorized source and protected-ref write tests reject correctly.
- [ ] Independent review of branch rules and runtime identity completed.

A passing public C-05 does not imply private-repository readiness, H-00 recovery or full Mode C PROVEN.
