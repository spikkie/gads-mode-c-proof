# GADS H-00 roadmap — canonical, no legacy compatibility

1. Clean H-00 baseline: complete (candidate E1).
2. Gateway adapter and read-only source provenance: candidate E1 complete.
3. Security-review REST ref updates: discovered fast-forward vs CAS distinction;
   replace with explicit GraphQL `beforeOid` and adversarial tests.
4. Public synthetic Git race proof: writer A observed; competing writer B
   produced a generic unknown error, not proof of GraphQL atomic comparison.
5. Obtain independent security approval and owner-controlled minimal trusted
   gateway/branch protection; no code from unprotected source may write.
6. Isolated **real** GraphQL `beforeOid` CAS test, conflict and timeout:
   pending approval, not delegated to read-only CI.
7. Durable outbox + authenticated target run correlation + actual model quota;
   no blind retries, no simulated budget represented as real billing.
8. Native unattended full-run crash recovery, independent adversarial QA,
   owner acceptance and only then adoption.

Never merge experimental stacked PRs automatically or reintroduce wrappers.
