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

# 3. The other two sealed examples added in Phase 79 get the same treatment.
#    Without this they would be the only committed sealed files nothing checks,
#    and a plaintext commit is exactly the accident this script exists to catch.
check_sealed() {
  local file="$1" key="$2"
  [ -f "$file" ] || { echo "FAIL: $file is missing"; exit 1; }
  grep -q "ENC\[AES256_GCM" "$file" || { echo "FAIL: $file is not SOPS-encrypted"; exit 1; }
  local dec
  dec="$(SOPS_AGE_KEY_FILE="$KEY" sops --decrypt "$file")"
  echo "$dec" | grep -q "$key" || { echo "FAIL: $file decrypted without $key"; exit 1; }
  echo "$dec" | grep -q "ENC\[AES256_GCM" && { echo "FAIL: $file did not decrypt"; exit 1; }
  echo "ok: $file seals and round-trips"
}
check_sealed "pg-app.sops.example.yaml" "password"
check_sealed "../../helm/pamv1/secrets.example.sops.yaml" "PAM_MASTER_KEY"

echo "OK: SOPS example is encrypted and round-trips with the demo key."
