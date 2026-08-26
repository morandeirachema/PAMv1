# SOPS-encrypted Kubernetes secrets (Phase 14)

PAMv1's secrets (`PAM_MASTER_KEY`, `PAM_API_KEY`, the database URL, …) must reach the
cluster without ever sitting in plaintext in git. This directory uses
**[SOPS](https://github.com/getsops/sops)** with **[age](https://age-encryption.org/)** to
encrypt *only the values* of a Kubernetes `Secret` — `kind`, `metadata` and the keys stay
readable, so the manifest is still reviewable and diffable, but the secret material is
sealed to a key only your operators (or a KMS/HSM) hold.

```
deploy/k8s/sops/
├── secrets.sops.example.yaml   # a real SOPS-encrypted Secret you can decrypt & study
├── age-example.key             # THROWAWAY demo key (public in this repo — DO NOT reuse)
├── apply.sh                    # decrypt → kubectl apply, plaintext never touches disk
├── verify.sh                   # CI check: proves the example really is encrypted and round-trips
└── README.md                   # this file
```

`verify.sh` is not decoration — CI runs it on every push
(`.github/workflows/ci.yml`, job `sops`). It fails the build if the committed
example is not actually encrypted, if it will not decrypt with the demo key, or
if a plaintext `CHANGE_ME` placeholder has leaked into it.

The encryption rules live in [`deploy/.sops.yaml`](../../.sops.yaml) (it governs the whole
`deploy/` subtree — both `k8s/sops/secrets*.yaml` and `helm/**/secrets*.yaml`): any matching
file gets its `data`/`stringData` values encrypted to the configured age recipient. SOPS also
works with **AWS/GCP/Azure KMS, HashiCorp Vault and PGP** recipients — mix them in
`deploy/.sops.yaml` for cloud KMS or multi-custodian setups. Because the config is not at the
repo root, pass it explicitly with `--config deploy/.sops.yaml` when **encrypting** (decrypting
needs no config — recipients are read from the sealed file's own metadata, so `apply.sh` and CI
are unaffected).

## Try the example (learning)

The committed example is encrypted to a **throwaway key that is public in this repo**, so
you can decrypt it and see the whole flow. Never seal real secrets to it.

```bash
# install the tools (Go module installs work anywhere Go is available)
go install github.com/getsops/sops/v3/cmd/sops@latest
go install filippo.io/age/cmd/age-keygen@latest

# decrypt the example to inspect it (values come back in cleartext)
SOPS_AGE_KEY_FILE=deploy/k8s/sops/age-example.key \
  sops --decrypt deploy/k8s/sops/secrets.sops.example.yaml
```

## Real usage

```bash
# 1. Generate YOUR key and keep the private half out of git.
#    .gitignore covers *.key, *.agekey, age.key and keys.txt — but check before
#    you commit, because deleting a private age key from a later
#    commit does not remove it from git history.
age-keygen -o age.key
grep 'public key' age.key            # copy the age1... recipient

# 2. Put that recipient in deploy/.sops.yaml (replace the example one)

# 3. Author your secret from the plaintext template, then seal it in place
#    (pass --config deploy/.sops.yaml since the config is not at the repo root)
cp deploy/k8s/secret.example.yaml deploy/k8s/sops/secrets.sops.yaml
$EDITOR deploy/k8s/sops/secrets.sops.yaml     # fill real values
sops --config deploy/.sops.yaml --encrypt --in-place deploy/k8s/sops/secrets.sops.yaml

# 4. Deploy — decrypt streams straight into kubectl, plaintext never hits disk
SOPS_AGE_KEY_FILE=age.key ./deploy/k8s/sops/apply.sh deploy/k8s/sops/secrets.sops.yaml
```

Edit a sealed file later with `sops --config deploy/.sops.yaml deploy/k8s/sops/secrets.sops.yaml`
(it decrypts into your editor and re-encrypts on save), and rotate recipients with
`sops --config deploy/.sops.yaml updatekeys deploy/k8s/sops/secrets.sops.yaml`.

### The database password, too

`pg-app.sops.example.yaml` seals the **CloudNativePG application credentials**. By default
CNPG generates that password itself, which puts a manual step in the middle of an
otherwise-IaC deployment: somebody reads it out of the running cluster and pastes it into
PAMv1's `PAM_DATABASE_URL`. Two copies of one password, kept in step by hand.

Sealing it makes the password an input instead of an output — uncomment
`bootstrap.initdb.secret.name` in [`../postgres-cnpg.yaml`](../postgres-cnpg.yaml) and both
sides read the same value. Create your own from the example first: that line makes the
cluster fail to bootstrap if the secret is absent.

## GitOps

- **Flux** — a **working example ships** in [`../flux/`](../flux/): a `GitRepository` plus
  two `Kustomization`s, one carrying `.spec.decryption.provider: sops` for the sealed
  secrets and one for the workload that `dependsOn` it. Two rather than one because only
  the secrets need the decryption key, and the workload must not start before its secret
  exists. Background: the [Flux SOPS guide](https://fluxcd.io/flux/guides/mozilla-sops/).
- **Helm** — a **working example ships** at
  [`../../helm/pamv1/secrets.example.sops.yaml`](../../helm/pamv1/secrets.example.sops.yaml):
  a real sealed values file for [`helm secrets`](https://github.com/jkroepke/helm-secrets),
  which decrypts it into a temp file for the duration of the command. This used to be
  described here with nothing behind it, which is how "supported" comes to mean
  "you work it out".
- **Argo CD** works via the [helm-secrets](https://github.com/jkroepke/helm-secrets) or
  [ksops](https://github.com/viaduct-ai/kustomize-sops) plugins. No example here — it needs
  a plugin installed into the Argo repo-server, which this repo cannot exercise honestly.

### Cloud KMS instead of (or alongside) age

`age` is the zero-dependency default, and in a cloud deployment its private key is itself
a secret somebody has to distribute — the problem it was meant to solve, one level down.
[`../../.sops.yaml`](../../.sops.yaml) carries commented recipient lines for **AWS KMS**,
**GCP KMS**, **Azure Key Vault** and **Vault Transit**. SOPS encrypts the data key to
*every* recipient on a rule and **any one** can decrypt, so adding a KMS beside `age` is
additive: CI and laptops keep using age, the cluster uses its cloud identity, and neither
needs the other's key. That is also the migration path — add the recipient, run
`sops updatekeys`, then remove the old one.

Nothing in PAMv1 *requires* SOPS — a plain `kubectl create secret` (or the Helm
`secret.data` values) still works. SOPS is the recommended way to keep the secret manifest
**in the same IaC repo** as the rest of the deployment without leaking it.

One wrinkle if you go that route: `.gitignore` deliberately ignores
`deploy/k8s/sops/secrets.sops.yaml` — the exact path step 2 above tells you to
create. That is a safety default, not a contradiction: it stops a *half-finished*
secrets file being committed before you have confirmed it is sealed. Once you
have run `verify.sh`-style checks on your own file and want GitOps to see it,
commit it explicitly with `git add -f`, or drop the ignore rule.
