-- DoubleLock: a per-credential second password, held by a named person,
-- required (in addition to normal RBAC) to reveal or check out the secret's
-- plaintext (Phase 135). Empty double_lock_holder (the default) means not
-- double-locked, so this column changes no existing credential's behavior
-- until an admin opts one in. The secret itself (secret_enc) is untouched;
-- double_lock_enc is a SEPARATE ciphertext keyed off the password directly
-- (never the KEK), so it is independent of -rotate-kek by construction.
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS double_lock_holder TEXT NOT NULL DEFAULT '';
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS double_lock_verifier TEXT NOT NULL DEFAULT '';
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS double_lock_enc TEXT NOT NULL DEFAULT '';
