# Sourcing PAMv1's bootstrap secrets from CyberArk Conjur (Phase 18)

PAMv1 can fetch its **own** bootstrap secrets — `PAM_MASTER_KEY`, `PAM_API_KEY`,
`PAM_DATABASE_URL`, the break-glass hash, and the broker audit keys — from a
[CyberArk Conjur](https://www.conjur.org/) instance at startup, instead of from a
Kubernetes Secret. This is the **runtime-broker** alternative to the
[SOPS GitOps sealing](../sops/) (Phase 14).

**Both mechanisms ship; neither is mandatory.** SOPS stays the zero-dependency
default (great for the demo, air-gapped/OT sites, and simple GitOps). Conjur is
opt-in for shops that already run it and want machine-identity auth, central
rotation, and per-access audit of PAMv1's own secrets.

## How PAMv1 uses Conjur

At boot, when `PAM_CONJUR_URL` is set, PAMv1 authenticates to Conjur and fills
**any empty** bootstrap `PAM_*` secret from the variables under
`PAM_CONJUR_POLICY_PREFIX` (default `pamv1`):

| Bootstrap secret | Conjur variable |
|---|---|
| `PAM_MASTER_KEY` | `pamv1/master-key` |
| `PAM_API_KEY` | `pamv1/api-key` |
| `PAM_DATABASE_URL` | `pamv1/database-url` |
| `PAM_BREAK_GLASS_KEY_HASH` | `pamv1/break-glass-key-hash` |
| `PAM_BROKER_AUDIT_KEY` | `pamv1/broker-audit-key` |
| `PAM_BROKER_AUDIT_SIGN_SEED` | `pamv1/broker-audit-sign-seed` |

At startup an **explicit environment value wins** (Conjur only fills gaps), and a
variable that isn't defined in Conjur (HTTP 404) is simply skipped — provide it
via env/SOPS instead. A configured-but-unreachable Conjur is **fail-loud**: the
server refuses to start rather than come up with empty secrets. Values are
trimmed, so a trailing newline from a file or a pipe never becomes part of a key.

After startup it depends on the secret. `PAM_API_KEY` and
`PAM_BREAK_GLASS_KEY_HASH` are **refreshed in place** when
`PAM_CONJUR_REFRESH_MIN` is set, as the shipped `deployment.yaml` does (every 60
minutes) — and then **Conjur wins** even over a value pinned in the environment.
The other four are read only at startup, and for three of them a restart is not
a rotation at all. See [Rotating without a restart](#rotating-without-a-restart).

## Setup

1. Load the policy and set the values (they live only in Conjur):

   ```bash
   conjur policy load -b root -f policy.yaml

   # Every value is piped in with `-f -` (Conjur CLI 8.1.3 or later), never
   # passed as `-v <value>`: an argument is visible to every local user in `ps`.
   # `read` and `printf` are shell builtins, so they start no process either.
   ./pam-server -genkey | conjur variable set -i pamv1/master-key -f -
   openssl rand -hex 24 | conjur variable set -i pamv1/api-key    -f -

   read -rs DB_URL      # postgres://pam:...@postgres:5432/pam?sslmode=verify-full
   printf '%s' "$DB_URL" | conjur variable set -i pamv1/database-url -f -

   # The break-glass hash must come from -hashkey, which hashes exactly what the
   # server compares. `echo "$KEY" | sha256sum` hashes the newline too: the
   # result is valid hex, so startup accepts it, and the key never matches.
   read -rs BREAK_GLASS_KEY
   printf '%s' "$BREAK_GLASS_KEY" | ./pam-server -hashkey \
     | conjur variable set -i pamv1/break-glass-key-hash -f -
   unset DB_URL BREAK_GLASS_KEY
   ```

   The AI-agent broker's two audit-chain keys are **optional**, and leaving them
   out is the default: PAMv1 generates each once and holds it in shared custody,
   sealed by the KEK. Set them in Conjur only to hold the keys yourself, and
   only **before the broker first runs**. On a cluster that already runs it, a
   `pamv1/broker-audit-key` that differs from the custody key stops the server
   (it refuses to fork the audit chain), and a new sign seed rotates the head
   signer, so earlier checkpoints verify only through
   `PAM_BROKER_AUDIT_SIGN_PREV`:

   ```bash
   openssl rand -base64 32 | conjur variable set -i pamv1/broker-audit-key       -f -
   openssl rand -base64 32 | conjur variable set -i pamv1/broker-audit-sign-seed -f -
   ```

2. Point pam-server at Conjur and pick an authenticator:

   **authn-jwt (recommended, Kubernetes-native — no bootstrap secret in Git).**
   The pod presents a projected service-account token; Conjur's
   [`authn-jwt`](https://docs.conjur.org/) verifies it against the cluster's JWKS.
   [`authn-jwt.yaml`](authn-jwt.yaml) is the Conjur side: the authenticator, and
   a host for the pod's service account that may read the bootstrap secrets.
   Load it after `policy.yaml`, and set the authenticator's variables. These are
   public values, not secrets, so `-v` is fine here:

   ```bash
   conjur policy load -b root -f authn-jwt.yaml
   A=conjur/authn-jwt/kubernetes
   conjur variable set -i $A/public-keys -v "{\"type\":\"jwks\",\"value\":$(kubectl get --raw /openid/v1/jwks)}"
   conjur variable set -i $A/issuer -v "$(kubectl get --raw /.well-known/openid-configuration | jq -r .issuer)"
   conjur variable set -i $A/token-app-property -v sub
   conjur variable set -i $A/identity-path      -v pamv1/k8s
   conjur variable set -i $A/audience           -v conjur
   ```

   Then enable the authenticator on the Conjur server (for Conjur Open Source,
   add `authn-jwt/kubernetes` to `CONJUR_AUTHENTICATORS`).
   `deployment.yaml` shows the projected-token volume and the env:

   ```
   PAM_CONJUR_URL=https://conjur.pamv1.svc.cluster.local
   PAM_CONJUR_AUTHN_JWT_SERVICE_ID=kubernetes
   PAM_CONJUR_JWT_FILE=/var/run/secrets/conjur/token
   PAM_CONJUR_CACERT=/etc/conjur/ca.pem
   ```

   **authn-api-key (portable).** A host API key (`conjur host rotate-api-key -i
   host/pamv1/pam-server`) in a small Secret:

   ```
   PAM_CONJUR_URL=https://conjur.example
   PAM_CONJUR_AUTHN_LOGIN=host/pamv1/pam-server
   PAM_CONJUR_API_KEY=<host api key>
   ```

3. Deploy: `kubectl apply -f deployment.yaml` (adjust the Conjur URL and CA; if
   you change the namespace or service account, change the host in
   `authn-jwt.yaml` to match).

## SOPS vs Conjur — when to use which

| | [SOPS](../sops/) (Phase 14) | Conjur (Phase 18) |
|---|---|---|
| Model | secret **at rest** in Git (GitOps) | secret **broker** fetched at runtime |
| Runtime dependency | none | a running Conjur |
| Secret in Git | encrypted | **none** (with authn-jwt) |
| Rotation / access audit | in Git history | **central, in Conjur** |
| Works air-gapped / `docker compose up` demo | yes | needs Conjur reachable |

PAMv1 already externalizes its **KEK** (Vault-Transit / AWS-KMS / PKCS#11);
sourcing the bootstrap secrets from Conjur is the same philosophy applied to the
values themselves.

## Env vars

| Variable | Purpose |
|---|---|
| `PAM_CONJUR_URL` | Conjur appliance URL — **presence enables the provider** |
| `PAM_CONJUR_ACCOUNT` | Conjur account (default `default`) |
| `PAM_CONJUR_POLICY_PREFIX` | variable-name prefix (default `pamv1`) |
| `PAM_CONJUR_AUTHN_LOGIN` / `PAM_CONJUR_API_KEY` | authn-api-key credentials |
| `PAM_CONJUR_AUTHN_JWT_SERVICE_ID` / `PAM_CONJUR_JWT_FILE` | authn-jwt service id + JWT file |
| `PAM_CONJUR_CACERT` | PEM CA bundle path for TLS to Conjur (optional) |
| `PAM_CONJUR_VARS` | per-variable override of the `<prefix>/<name>` convention: `PAM_API_KEY=prod/keys/api,...`. Unknown names and malformed ids stop the server (Phase 78/80) |
| `PAM_CONJUR_REFRESH_MIN` | minutes between re-reads of the refreshable secrets; `0` (default) is off (Phase 78/80) |
| `PAM_SECRETS_PROVIDER=conjur` | optional explicit enable (requires `PAM_CONJUR_URL`) |

## Rotating without a restart

With `PAM_CONJUR_REFRESH_MIN` set, every replica re-reads the secrets Conjur
**manages** and adopts changes in place — audited `config.secret_refreshed` under
actor `system-conjur`, which names the key and never the value.

**Only `PAM_API_KEY` and `PAM_BREAK_GLASS_KEY_HASH` are refreshable.** They are
pure comparison values, so replacing what the resolver compares against is
complete and instant. `PAM_MASTER_KEY` is the KEK — changing it does not rotate
the vault, it makes it undecryptable (`pam-server -rotate-kek`, offline, is the
path); `PAM_DATABASE_URL` is bound into a live pool; and the two broker audit
keys key the HMAC chain and its signatures. Those four are **never fetched** on
the refresh tick, so the KEK does not cross the network to produce a log line,
and the startup log names both lists.

Two things worth knowing before you rely on it:

- **Conjur must actually manage the variable.** The refresher probes at startup
  and refreshes only what it finds; if `pamv1/api-key` does not exist, the log
  says so rather than promising a rotation that never happens.
- **A variable you delete is not a revocation.** Removing or emptying it keeps
  the running value — a policy edit must never disable break-glass — and logs a
  warning. To retire a key, set a new value.
- **Refresh takes over a value pinned in the environment.** If `PAM_API_KEY` is
  set in the Deployment *and* `pamv1/api-key` exists, Conjur's value replaces
  the environment one on the first tick, and startup logs a warning naming it.
  Without refresh the environment value still wins.

The four pinned secrets change only on a restart, and only one of them is
safe to change that way:

| Changed in Conjur, then restarted | What happens |
|---|---|
| `pamv1/database-url` | the new URL is used |
| `pamv1/master-key` | every stored secret is undecryptable — rotate with `pam-server -rotate-kek`, offline, instead |
| `pamv1/broker-audit-key` | the server refuses to start: the key differs from the chain key in shared custody |
| `pamv1/broker-audit-sign-seed` | the head signer rotates; set `PAM_BROKER_AUDIT_SIGN_PREV` to the old public key first, or earlier checkpoints stop verifying |

On the authn-jwt deployment in `deployment.yaml`, the projected token expires
every 10 minutes and the kubelet rewrites the file; the client re-reads it on
every authenticate, so refresh keeps working past the first expiry.

## Deferred

Pushing PAMv1's *managed* secrets out to Conjur (Secrets-Hub-style sync) remains
a documented follow-on. Runtime secret refresh and the per-variable override map
**shipped in Phase 78** and were rebuilt in Phase 80 — see "Rotating without a
restart" above.
