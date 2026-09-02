-- Test fixture: a conventional backend + Postgres project. NOT Supabase.
--
-- This is the false positive trap the RLS rule has to avoid. Row Level Security
-- is only *required* when the database is exposed straight to the browser, as
-- Supabase and PostgREST do. Here the database sits behind an API server and is
-- never reachable by a client, so these tables need no RLS at all.
--
-- Reporting this project would be a serious false positive, and the kind that
-- makes an experienced developer close the tab.

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
