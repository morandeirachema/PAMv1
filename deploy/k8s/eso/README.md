# pamv1 as an External Secrets Operator backend

pamv1 delivers a granted secret to a workload in Kubernetes through
[External Secrets Operator](https://external-secrets.io/)'s generic **webhook**
provider. ESO templates a request, pamv1 authenticates the application key,
checks the grant, audits the retrieval fail-closed, and answers JSON; ESO reads
`$.secret` out of it and writes a Kubernetes `Secret`.

## What this is, and what it is not

This makes pamv1 a **source** of secrets for workloads. It does not make pamv1
manage Kubernetes Secrets, and it is not the same thing as pamv1's *own* secrets
in a cluster (those are SOPS-sealed and decrypted by Flux — see
[`../sops/`](../sops/) and [`../flux/`](../flux/)).

ESO's webhook provider does not support listing or discovery, so every secret is
named explicitly. That is a property of the provider, not a gap here.

## Setup

1. **Mint an application identity.** The token is shown exactly once.

   ```bash
   curl -X POST -H "X-API-Key: $PAM_API_KEY" \
        -d '{"name":"cluster-eso","owner":"platform-team"}' \
        https://pamv1/v1/apps
   ```

2. **Grant it the credential**, then **name the grant**. The alias is what the
   manifest references, and it is stable across environments and restores in a
   way a credential row id is not:

   ```bash
   curl -X POST -H "X-API-Key: $PAM_API_KEY" \
        -d '{"credential_id":42}' https://pamv1/v1/apps/$APP_ID/grants
   curl -X POST -H "X-API-Key: $PAM_API_KEY" \
        -d '{"alias":"prod-db-password"}' \
        https://pamv1/v1/apps/$APP_ID/grants/$GRANT_ID/alias
   ```

   An alias may contain letters, digits, dot, dash and underscore — it travels in
   a URL path segment, and a name that needs escaping is a name that will
   eventually be addressed wrongly.

3. **Give the cluster the key and the CA**, then apply the manifests:

   ```bash
   kubectl -n pamv1 create secret generic pamv1-app-key --from-literal=token='<token>'
   kubectl -n pamv1 create secret generic pamv1-ca --from-file=ca.crt=/path/to/pam-ca.crt
   kubectl -n pamv1 apply -f secretstore.yaml -f externalsecret.yaml
   ```

## Status codes, and why one of them is destructive

ESO assigns meaning to the response code, and **404 means "this secret no longer
exists" — ESO deletes the Kubernetes Secret it manages.** pamv1 therefore answers:

| Situation | Code | Why |
|---|---|---|
| Granted, alias resolves | `200` | the secret, at `$.secret` |
| No such alias for this app | `404` | it really is gone; letting ESO clean up is correct |
| Grant **revoked** | `404` on the by-alias route | the alias lives on the grant, so revoking it removes the name — **and ESO removes the Secret.** That is intended: revocation propagates, and a plaintext secret left sitting in a Kubernetes Secret after access is withdrawn is the worse outcome |
| Credential never granted, addressed by id | `403` | a refusal, not a deletion |
| `PAM_REVEAL_DISABLED` is set | `403` | policy turned delivery off; same reasoning |
| Bad or missing application key | `401` | |

`TestESOStatusContract` pins all of these, and fails with an explicit message if
a refusal is ever turned into a 404.

## Verifying against a real cluster

The contract above is covered by tests against an in-process server. **End-to-end
against a running ESO in a real cluster is not verified in CI** — it needs a
cluster, which this project does not have; it is catalogued in
[`docs/EXTERNAL-INFRA-GAPS.md`](../../../docs/EXTERNAL-INFRA-GAPS.md) with the
rest of the infra-bound items. When you do test it, this is what to check:

- [ ] `kubectl get externalsecret app-db-credentials` reaches `SecretSynced`.
- [ ] The created `Secret` holds the vaulted password under `password`.
- [ ] pamv1's audit trail shows `app.secret_retrieved` with
      `alias:prod-db-password`, once per refresh — and **never the secret itself**.
- [ ] Rotate the credential in pamv1; after `refreshInterval`, the Kubernetes
      Secret carries the new value.
- [ ] **Revoke the grant.** The Kubernetes Secret **is removed** — the alias goes
      with the grant, the route answers 404, and ESO cleans up. That is the
      intended behaviour: revocation propagates. Plan for it, because the workload
      loses the Secret rather than merely stopping refreshes.
- [ ] **Turn on the reveal kill switch** (`PAM_REVEAL_DISABLED=true`) with the
      grant intact. This is the case that must **not** delete anything: the
      `ExternalSecret` should go to `SecretSyncedError` and the Kubernetes Secret
      must **still exist** with its last value. If it disappears, pamv1 answered
      404 where it must answer 403 — please report that.
