-- Test fixture: the drop that retires legacy_notes.
DROP TABLE IF EXISTS public.legacy_notes CASCADE;

-- And the dangerous case, in the same file: a commented-out drop of a table
-- that is still very much live and still has no RLS. Honouring this would
-- delete "orders" from the schema and silently retire a real finding — a
-- comment must never be able to hide a vulnerability.
-- DROP TABLE public.orders;

-- A string is not a statement. Reading through the quotes here would delete
-- "orders" from the replay and silently retire a real finding — one sentence of
-- SQL hiding a live table with no RLS.
INSERT INTO audit_log (note) VALUES ('DROP TABLE public.orders;');

-- Nor is a function body. The table named in here does not exist.
CREATE OR REPLACE FUNCTION public.noop() RETURNS void AS $fn$
  -- CREATE TABLE public.ghost_from_body (id uuid);
  SELECT 1;
$fn$ LANGUAGE sql;
