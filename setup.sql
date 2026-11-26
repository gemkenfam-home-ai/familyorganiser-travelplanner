-- =====================================================================
-- Family Trip Portal — Supabase setup
-- Paste this whole file into Supabase > SQL Editor > New query > Run.
-- BEFORE running: change the email and name on the last line to yours.
-- Safe to run again; it won't duplicate anything.
-- =====================================================================

-- 1. Who is allowed in ------------------------------------------------
create table if not exists public.family (
  email     text primary key check (email = lower(email)),
  name      text not null default '',
  role      text not null default 'member' check (role in ('admin','member')),
  added_at  timestamptz not null default now()
);

-- 2. Trips (one row per trip; travellers, budget, expenses live in `data`)
create table if not exists public.trips (
  id          text primary key,
  data        jsonb not null,
  updated_at  timestamptz not null default now(),
  updated_by  text
);

-- 3. Helper checks: is the signed-in person on the family list? an admin?
create or replace function public.is_family() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.family
                 where email = lower(coalesce(auth.jwt() ->> 'email','')));
$$;

create or replace function public.is_family_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.family
                 where email = lower(coalesce(auth.jwt() ->> 'email',''))
                   and role = 'admin');
$$;

-- Stamp who changed a trip and when
create or replace function public.touch_trip() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  new.updated_at := now();
  new.updated_by := lower(coalesce(auth.jwt() ->> 'email', new.updated_by));
  return new;
end $$;
drop trigger if exists trips_touch on public.trips;
create trigger trips_touch before insert or update on public.trips
  for each row execute function public.touch_trip();

-- 4. Row-level security: nobody outside the family list sees anything
alter table public.family enable row level security;
alter table public.trips  enable row level security;

drop policy if exists family_read   on public.family;
drop policy if exists family_admin  on public.family;
create policy family_read  on public.family for select to authenticated using (public.is_family());
create policy family_admin on public.family for all    to authenticated
  using (public.is_family_admin()) with check (public.is_family_admin());

drop policy if exists trips_read   on public.trips;
drop policy if exists trips_insert on public.trips;
drop policy if exists trips_update on public.trips;
drop policy if exists trips_delete on public.trips;
create policy trips_read   on public.trips for select to authenticated using (public.is_family());
create policy trips_insert on public.trips for insert to authenticated with check (public.is_family());
create policy trips_update on public.trips for update to authenticated using (public.is_family()) with check (public.is_family());
create policy trips_delete on public.trips for delete to authenticated using (public.is_family_admin());

-- 5. Private receipts bucket (photos / PDFs, max 20 MB each)
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('receipts','receipts', false, 20971520, array['image/*','application/pdf'])
on conflict (id) do update set public = false;

drop policy if exists receipts_read   on storage.objects;
drop policy if exists receipts_write  on storage.objects;
drop policy if exists receipts_delete on storage.objects;
create policy receipts_read   on storage.objects for select to authenticated
  using (bucket_id = 'receipts' and public.is_family());
create policy receipts_write  on storage.objects for insert to authenticated
  with check (bucket_id = 'receipts' and public.is_family());
create policy receipts_delete on storage.objects for delete to authenticated
  using (bucket_id = 'receipts' and public.is_family());

-- 6. Live updates when another family member changes a trip
do $$ begin
  alter publication supabase_realtime add table public.trips;
exception when duplicate_object then null; end $$;

-- 7. YOU, as the first admin  ⟵ change these two values
insert into public.family (email, name, role)
values (lower('kennethpooncx@gmail.com'), 'Kenneth', 'admin')
on conflict (email) do update set role = 'admin';
