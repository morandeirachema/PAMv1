---
name: Bug report
about: Something behaves differently than the docs or code say it should
title: ""
labels: bug
---

<!-- Security issue? Do NOT open a public issue — see SECURITY.md. -->

**What happened**

**What you expected**

**How to reproduce**
Steps, the relevant `PAM_*` configuration (names and shapes only — NEVER paste
a real key, password, hash or hostname), and whether the store was `memory` or
PostgreSQL.

**Version**
Output of `pam-server -version` (or the image tag), and how it was deployed
(local build / docker-compose / Helm / raw K8s / Terraform).

**Logs / audit events**
Relevant log lines or audit actions, with secrets redacted.
