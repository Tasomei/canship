-- 后续迁移会删除此表，最终结果中不应出现。
CREATE TABLE IF NOT EXISTS public.legacy_notes (
  id uuid PRIMARY KEY,
  body text
);
