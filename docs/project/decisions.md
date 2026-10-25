# Architecture decisions

- **D-001:** No backward compatibility for unaccepted C05–C10 experimental code.
- **D-002:** H-00 transitions are pure; external state CAS belongs to a later
  separately approved trusted gateway.
- **D-003:** Uncertain effects are sticky `UNKNOWN`; never re-dispatch merely
  because an API response was lost or a lease timed out.
- **D-004:** Reserve synthetic budget before a potential call; never claim
  real billable-cost enforcement without independent provider metering.
- **D-005:** Immutable source SHA and correlation are mandatory; event input
  must come from an authenticated trusted gateway, not arbitrary JSON.
- **D-006:** No write-capable GitHub token in branch CI; historic evidence is
  preserved by references to commits and workflows, not executable adapters.
