-- Slack identity mapping (Phase 236): the review of Phase 234 found that a
-- Slack button click became a PAMv1 actor in its own namespace
-- ("slack:<handle>"), so four-eyes and distinct-approver checks — both
-- string comparisons against PAMv1 usernames — could never recognise the
-- same human. slack_user_id links a user row to one Slack member ID (the
-- stable workspace-scoped "U…" id Slack sends as user.id, never the
-- changeable display handle); the interactivity handler resolves a click to
-- this row and decides AS that PAMv1 identity, or refuses the click.
--
-- Empty default so every existing row is unaffected (an unlinked user simply
-- cannot decide from Slack); the partial unique index leaves any number of
-- rows sharing the empty default alone while refusing two humans to claim
-- the same member.
ALTER TABLE users ADD COLUMN IF NOT EXISTS slack_user_id TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX IF NOT EXISTS users_slack_user_id_idx ON users (slack_user_id) WHERE slack_user_id <> '';
