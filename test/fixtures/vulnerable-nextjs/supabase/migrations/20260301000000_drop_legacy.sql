-- 删除历史表。
DROP TABLE IF EXISTS public.legacy_notes CASCADE;

-- 注释不能删除仍存在的表。
-- 示例：DROP TABLE public.orders;

-- 字符串中的语句不参与结构重放。
INSERT INTO audit_log (note) VALUES ('DROP TABLE public.orders;');

-- 函数定义不会直接创建表。
CREATE OR REPLACE FUNCTION public.noop() RETURNS void AS $fn$
  -- 示例：CREATE TABLE public.ghost_from_body (id uuid);
  SELECT 1;
$fn$ LANGUAGE sql;
