-- Subject-indexed grant lookup (Phase 189).
--
-- Every grant query pamv1 had was TARGET-indexed: "who may reach this target",
-- answered by target_grants_target_idx and safe_members_safe_idx. The question
-- an investigator actually asks is the other one — "what can this subject
-- reach?" — and answering it meant reading every target's grants and filtering
-- in Go, two reads per target.
--
-- GrantsForSubjects asks it directly, joining both grant tables on
-- (subject_type, subject). These two indexes are what keep that from being a
-- sequential scan of both tables on an estate large enough for the question to
-- matter. The column order puts subject_type first only because it matches how
-- the pair is written everywhere else; both columns are always supplied
-- together, so either order would serve the same query.
--
-- Not UNIQUE: a subject legitimately holds many grants (that is the answer the
-- query returns), and safe membership is unique per (safe, subject), which the
-- existing constraint already enforces.
CREATE INDEX IF NOT EXISTS target_grants_subject_idx ON target_grants (subject_type, subject);
CREATE INDEX IF NOT EXISTS safe_members_subject_idx  ON safe_members  (subject_type, subject);
