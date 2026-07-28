#!/usr/bin/env bash
# CI check for the SOPS example (Phase 14): prove the committed example is really
# encrypted (guards against an accidental plaintext commit) and that it round-trips
# with the throwaway demo key. Requires sops + age on PATH.
set -euo pipefail

cd "$(dirname "$0")"
FILE="secrets.sops.example.yaml"
KEY="age-example.key"

# 1. The sealed values must be encrypted, not plaintext.
grep -q "ENC\[AES256_GCM" "$FILE" || { echo "FAIL: $FILE is not SOPS-encrypted"; exit 1; }
# The sentinel is the placeholder the template actually uses (see
# ../secret.example.yaml). It used to read "REPLACE_WITH_pam-server", a string
# that appears nowhere in this repo — so this guard could never fire, which is
# the worst state for a safety check: present, green, and asleep.
grep -q "CHANGE_ME" "$FILE" && { echo "FAIL: plaintext placeholder leaked into $FILE"; exit 1; }

# 2. It must decrypt cleanly with the demo key and yield the expected keys.
out="$(SOPS_AGE_KEY_FILE="$KEY" sops --decrypt "$FILE")"
for k in PAM_MASTER_KEY PAM_API_KEY PAM_DATABASE_URL; do
  echo "$out" | grep -q "$k" || { echo "FAIL: decrypted output missing $k"; exit 1; }
done
echo "$out" | grep -q "ENC\[AES256_GCM" && { echo "FAIL: values did not decrypt"; exit 1; }

echo "OK: SOPS example is encrypted and round-trips with the demo key."
