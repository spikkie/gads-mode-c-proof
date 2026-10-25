# GADS status — exact-old-SHA atomic state update candidate

2026-10-25: v0.2.1 source E1 passed 57/57 tests. The security review found
that REST `force:false` is only a fast-forward check; 0.2.2 replaces the
proposed state update with injectable GraphQL `updateRefs` carrying
`beforeOid` and `afterOid` plus fail-closed unknown-ack handling.

Live GitHub public synthetic branch `qualification/gads-cas-isolated-20261025`
was initialized from protected main. Competing writer A succeeded; writer B
returned an unknown GitHub GraphQL error. Live ref readback found winner A,
generation 1. This is **not** a live end-to-end `updateRefs(beforeOid)`
proof and must not be called approved atomic CAS.

Final-head CI and independent review remain required. Security issue #8,
unprotected legacy branch writers, human approval rules, provider billing
and unattended recovery remain OPEN. No merged PR or main/private writes.

## Writer authorization preflight — 2026-10-25

[Read-only E1 #40192165262](https://github.com/spikkie/gads-mode-c-proof/actions/runs/40192165262)
PASS: 89/89 tests. [Live authority gate #40192165265](https://github.com/spikkie/gads-mode-c-proof/actions/runs/40192165265)
BLOCKED as expected, reporting 16 unresolved control conditions at initial
source SHA `195a5f3e60a58933d5bd4d9ab5e1f306797907cc`.

Draft PR #13 (stacked on #12) has been added to the reviewer scope; final
head must be requalified. This does not deploy a privileged writer. No
separate state-only repository, App installation, source-main merge or token
grant exists. SEC-01 / SEC-02 and full Mode C remain open.
