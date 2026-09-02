-- Test fixture: schema where RLS is forgotten on some tables.

-- Fatal: created and never secured. Anyone with the public anon key can read
-- every row, including the email addresses.
create table public.profiles (
  id uuid primary key references auth.users on delete cascade,
  email text not null,
  full_name text,
  created_at timestamptz default now()
);

-- Fatal: no schema qualifier, so it defaults to public. Also unsecured.
create table if not exists "orders" (
  id bigserial primary key,
  user_id uuid not null,
  total_cents integer not null,
  stripe_payment_id text
);

-- Correct: this one is secured below and must not be reported.
create table public.audit_log (
  id bigserial primary key,
  actor uuid,
  action text not null
);

alter table public.audit_log enable row level security;

create policy "audit_log is readable by its actor"
  on public.audit_log for select
  using (auth.uid() = actor);

-- Must not be reported: commented-out DDL is not a real table.
-- create table public.draft_table (id int);
