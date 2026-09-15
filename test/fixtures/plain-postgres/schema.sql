-- 普通后端数据库位于 API 服务之后，不按 Supabase 直接访问模式检查。

create table public.users (
  id bigserial primary key,
  email text not null unique,
  password_hash text not null
);

create table public.sessions (
  id uuid primary key,
  user_id bigint not null references public.users(id),
  expires_at timestamptz not null
);

create table public.invoices (
  id bigserial primary key,
  user_id bigint not null references public.users(id),
  amount_cents integer not null
);
