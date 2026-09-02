-- Test fixture: RLS turned on and then turned back off again.
--
-- This is the state where silence is most dangerous: somebody did think about
-- Row Level Security on this table, and then changed their mind. A replay that
-- only knows how to switch protection on reads the first statement, never the
-- second, and calls the table safe.
CREATE TABLE public.invoices (
  id uuid PRIMARY KEY,
  amount numeric
);
ALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.invoices DISABLE ROW LEVEL SECURITY;

-- And a rename, with protection that has to follow the table. Reporting
-- "receipts" here would name something that no longer exists.
CREATE TABLE public.receipts (id uuid PRIMARY KEY);
ALTER TABLE public.receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.receipts RENAME TO payment_receipts;
