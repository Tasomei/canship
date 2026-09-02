-- Test fixture: every table here is secured correctly. Any finding is a false positive.

create table public.profiles (
  id uuid primary key references auth.users on delete cascade,
  email text not null,
  full_name text
);

alter table public.profiles enable row level security;

create policy "profiles are viewable by their owner"
  on public.profiles for select
  using (auth.uid() = id);

-- RLS enabled in a separate statement further down the file, and for a table
-- written without a schema qualifier — the rule has to match these up.
create table if not exists orders (
  id bigserial primary key,
  user_id uuid not null,
  total_cents integer not null
);

-- Internal schema: not reachable through the public API, so RLS is not required
-- here and reporting it would be noise.
create table auth.custom_sessions (
  id uuid primary key,
  token text
);

alter table public.orders enable row level security;

create policy "orders are viewable by their owner"
  on public.orders for select
  using (auth.uid() = user_id);
