# GADS v0.2.2 — candidate

**NOT RELEASED / NOT MERGED / NOT ADOPTED**

Security gate response: REST `force:false` cannot claim exact-head CAS.
Gateway now requires injectable GraphQL `updateRefs` with explicit
`beforeOid`. Unknown responses fail closed without a blind second write.

The isolated public Git branch race has observed a winning write, a failed
second connector call of unknown classification and preserved winner via GET.
This is not a live authenticated atomic GraphQL test of the new gateway.

No Actions write token, new AI job, private repo change or main merge.
Security issue #8 and full Mode C remain open.
