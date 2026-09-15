-- 启用后又关闭行级安全，最终必须报告未保护状态。
CREATE TABLE public.invoices (
  id uuid PRIMARY KEY,
  amount numeric
);
ALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.invoices DISABLE ROW LEVEL SECURITY;

-- 重命名后应保留表的安全状态。
CREATE TABLE public.receipts (id uuid PRIMARY KEY);
ALTER TABLE public.receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.receipts RENAME TO payment_receipts;
