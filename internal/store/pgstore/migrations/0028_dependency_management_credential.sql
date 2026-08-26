-- Phase 61: a dependent account can name the credential PAMv1 connects WITH to
-- update it.
--
-- Until now propagation logged into the consumer's host as the rotated service
-- account itself, using its brand-new password. That asks the wrong account for
-- the wrong rights: reconfiguring a service, task or app pool needs remote
-- management and local-administrator rights on that host, which is precisely
-- what a service account is not supposed to have — and a hardened one usually
-- cannot log on remotely at all, so propagation simply failed where it was most
-- needed. It also had nowhere to stand when the rotation was being run to
-- recover a broken account.
--
-- NULL keeps the previous behaviour (connect as the rotated account), so an
-- existing deployment sees no change until an operator sets it.
--
-- Deliberately NOT a foreign key. The reference records an operator's INTENT —
-- "manage this consumer with that credential" — and the two cascade options
-- both lose it: ON DELETE SET NULL would silently fall back to logging in as
-- the rotated account (the behaviour the operator chose to move away from), and
-- ON DELETE RESTRICT would make an unrelated credential undeletable. Keeping a
-- dangling id lets propagation fail CLOSED and say exactly why
-- (`credential.dependency_failed reason:management-credential-missing`), which
-- is the only outcome that neither surprises nor blocks.

ALTER TABLE credential_dependencies
    ADD COLUMN IF NOT EXISTS management_credential_id BIGINT;
