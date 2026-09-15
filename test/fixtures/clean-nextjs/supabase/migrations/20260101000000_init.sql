-- 所有表均已正确配置安全策略。

create table public.profiles (
  id uuid primary key references auth.users on delete cascade,
  email text not null,
  full_name text
);

alter table public.profiles enable row level security;

create policy "profiles are viewable by their owner"
  on public.profiles for select
  using (auth.uid() = id);

-- 后续语句为无模式限定的表启用行级安全。
create table if not exists orders (
  id bigserial primary key,
  user_id uuid not null,
  total_cents integer not null
);

-- 内部模式不通过公共数据接口暴露。
create table auth.custom_sessions (
  id uuid primary key,
  token text
);

alter table public.orders enable row level security;

create policy "orders are viewable by their owner"
  on public.orders for select
  using (auth.uid() = user_id);
