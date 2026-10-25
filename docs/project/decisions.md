# Architecture decisions — canonical GADS

- **D-001:** No backward compatibility for experimental C05–C10 source.
- **D-002:** H-00 pure deterministic transitions; durable effects in one small
  separately reviewed GitHub gateway.
- **D-003:** Any failed or ambiguous dispatch/lease is sticky `UNKNOWN` with
  no blind automatic retry.
- **D-004:** Reserve synthetic units before dispatch, but do not conflate them
  with actual premium-request or monetary billing enforcement.
- **D-005:** Source ref is fixed in trusted code and pinned to reviewed SHA;
  repository-scoped GitHub token rights are NOT restricted to this ref.
- **D-006:** GitHub CAS: commit against observed ref SHA, non-force update,
  readback; a CAS race blocks instead of automatic retry.
- **D-007:** Actor, workflow, SHA and run-name correlation must be fetched
  from GitHub by the gateway. API `display_title` proof remains pending.
- **D-008:** No feature-branch execution with write authority, no automatic
  protected-main merge before human/independent approval.
