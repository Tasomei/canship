-- Test fixture: a table with no RLS, created here and dropped two migrations
-- later. It must not be reported: migrations are append-only, so reading them
-- as a set rather than a sequence invents tables that do not exist.
CREATE TABLE IF NOT EXISTS public.legacy_notes (
  id uuid PRIMARY KEY,
  body text
);
