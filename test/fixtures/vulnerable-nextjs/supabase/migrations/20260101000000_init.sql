-- 部分表未启用行级安全的夹具。

-- 建表后未启用保护，数据可能通过公开接口暴露。
create table public.profiles (
  id uuid primary key references auth.users on delete cascade,
  email text not null,
  full_name text,
  created_at timestamptz default now()
);

-- 省略模式时属于公共模式，且未启用保护。
create table if not exists "orders" (
  id bigserial primary key,
  user_id uuid not null,
  total_cents integer not null,
  stripe_payment_id text
);

-- 后续启用保护的表不应报告。
create table public.audit_log (
  id bigserial primary key,
  actor uuid,
  action text not null
);

alter table public.audit_log enable row level security;

create policy "audit_log is readable by its actor"
  on public.audit_log for select
  using (auth.uid() = actor);

-- 注释中的建表语句不应参与重放。
-- 示例：create table public.draft_table (id int);
