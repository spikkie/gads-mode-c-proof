# Decisions

- D1: Synthetic-only public materials; never mirror any private repository.
- D2: GitHub Free protected public `main` is a mandatory server-side gate.
- D3: One reviewed exact-SHA approval variable gates model and writer jobs; fail closed by default.
- D4: Publisher may create only a draft PR into `main` with two file changes; no merge/approval APIs.
- D5: One successful public proof is not permission to publish into a private repository.
- D6: Additional architecture/prototypes must be justified by an observed C-05 failure.
