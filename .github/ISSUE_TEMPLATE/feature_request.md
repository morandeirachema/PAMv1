---
name: Feature request
about: Propose a capability or improvement
title: ""
labels: enhancement
---

**The problem**
What can't you do, observe or control today? For access-control features, say
who the actors are (operator / approver / auditor / agent) and what should stop
whom from doing what.

**Proposed shape**
How it might work in PAMv1's model (chokepoint brokering, JIT injection,
audited actions, deny-by-default). A rough sketch is fine.

**Prior art**
How CyberArk / Wallix / Teleport / Vault or another system solves this, if you
know — [ROADMAP.md](../../ROADMAP.md) tracks coverage against them, so this
helps place the request.

**Scope check**
Anything needing external infrastructure (a KDC, real HSM, cloud accounts,
network hardware) lands in
[docs/EXTERNAL-INFRA-GAPS.md](../../docs/EXTERNAL-INFRA-GAPS.md) rather than
being faked — flag it if that applies.
