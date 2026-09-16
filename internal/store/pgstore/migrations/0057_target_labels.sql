-- Target labels and label rules (Phase 250). A target carries a canonical
-- label set ("env=prod,tier=db", see internal/store/labels.go); a label rule
-- grants or DENIES a subject access to every target whose labels match its
-- selector, without naming any target. Empty labels — every row that predates
-- this migration — match no selector, so no existing target gains or loses
-- access when this runs.
--
-- A deny rule is the first authorization row in PAMv1 that says no: it refuses
-- ahead of the admin bypass (break-glass excepted), which is why the selector
-- is validated on write and never guessed at on read.
ALTER TABLE targets ADD COLUMN IF NOT EXISTS labels TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS label_rules (
    id           BIGSERIAL PRIMARY KEY,
    selector     TEXT NOT NULL,
    subject_type TEXT NOT NULL,
    subject      TEXT NOT NULL,
    effect       TEXT NOT NULL DEFAULT 'allow',
    permissions  TEXT NOT NULL DEFAULT 'use,retrieve',
    expires_at   TIMESTAMPTZ,
    time_frame   TEXT NOT NULL DEFAULT '',
    created_by   TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT label_rules_effect_check CHECK (effect IN ('allow', 'deny')),
    CONSTRAINT label_rules_subject_type_check CHECK (subject_type IN ('user', 'role'))
);

-- One rule per (selector, subject, effect): re-adding the same rule is a
-- conflict, not a silent duplicate that has to be revoked twice.
CREATE UNIQUE INDEX IF NOT EXISTS label_rules_unique_idx
    ON label_rules (selector, subject_type, subject, effect);
CREATE INDEX IF NOT EXISTS label_rules_expires_at_idx
    ON label_rules (expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS targets_labels_idx ON targets (labels) WHERE labels <> '';
