# Security boundary — public synthetic candidate

No private repository source, secrets, customer names, topology, credentials,
external deployment, or production data may enter this repository.

Candidate CI uses read-only GitHub permissions with pinned checkout and
`persist-credentials: false`. New H-00 code contains no HTTP, Git, model
or repository-write operations. Any future effecting gateway must read
authoritative GitHub evidence itself rather than accepting a supplied payload.

Pure transition correctness does not establish real side-effect exactly-once,
protected branch controls, authenticated provider usage or actual spend caps.

Full Mode C **NOT PROVEN / NOT ADOPTED**. Security issues #1 and #8 remain open.
