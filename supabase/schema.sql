-- BRUTE Studio : base de données Supabase
-- À coller dans Supabase > SQL Editor > New query, puis "Run".
-- Remplacer CODE_SALON et CODE_GERANT par les vrais codes avant d'exécuter
-- (ne jamais publier les vrais codes dans ce dépôt).

create extension if not exists pgcrypto;

-- Réglages privés (codes d'inscription) : RLS activée sans aucune règle,
-- donc illisibles depuis l'appli.
create table if not exists public.private_settings (
  key text primary key,
  value text not null
);
alter table public.private_settings enable row level security;
insert into public.private_settings (key, value) values
  ('salon_code', 'CODE_SALON'),
  ('gerant_code', 'CODE_GERANT')
on conflict (key) do update set value = excluded.value;

-- Profils : un par compte (coiffeur ou gérant)
create table if not exists public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  username text not null unique,
  display_name text not null,
  role text not null default 'coiffeur' check (role in ('coiffeur', 'gerant')),
  created_at timestamptz not null default now()
);
alter table public.profiles enable row level security;

create or replace function public.is_gerant()
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role = 'gerant');
$$;

-- À la création d'un compte : vérifie le code et crée le profil
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
declare
  meta jsonb := coalesce(new.raw_user_meta_data, '{}'::jsonb);
  r text := 'coiffeur';
begin
  if coalesce(meta->>'gerant_code', '') <> ''
     and meta->>'gerant_code' = (select value from public.private_settings where key = 'gerant_code') then
    r := 'gerant';
  elsif coalesce(meta->>'salon_code', '') is distinct from (select value from public.private_settings where key = 'salon_code') then
    raise exception 'Code incorrect';
  end if;
  insert into public.profiles (id, username, display_name, role)
  values (new.id, lower(meta->>'username'), coalesce(nullif(meta->>'display_name', ''), meta->>'username'), r);
  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

drop policy if exists "profils lisibles" on public.profiles;
create policy "profils lisibles" on public.profiles
  for select to authenticated using (id = auth.uid() or public.is_gerant());

-- Transformations (une par visuel avant/après)
create table if not exists public.transformations (
  id uuid primary key default gen_random_uuid(),
  coiffeur_id uuid references auth.users (id) on delete set null default auth.uid(),
  coiffeur_name text not null,
  client_prenom text not null,
  client_tel text,
  client_mail text,
  consent_photo boolean not null default true,
  consent_pub boolean not null default false,
  format text,
  template text,
  image_path text not null,
  thumb_path text not null,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default (now() + interval '1 year')
);
alter table public.transformations enable row level security;
create index if not exists transformations_coiffeur_idx on public.transformations (coiffeur_id, created_at desc);

drop policy if exists "tx ajouter" on public.transformations;
drop policy if exists "tx lire" on public.transformations;
drop policy if exists "tx modifier" on public.transformations;
drop policy if exists "tx supprimer" on public.transformations;
create policy "tx ajouter" on public.transformations
  for insert to authenticated with check (coiffeur_id = auth.uid());
create policy "tx lire" on public.transformations
  for select to authenticated using (coiffeur_id = auth.uid() or public.is_gerant());
create policy "tx modifier" on public.transformations
  for update to authenticated using (coiffeur_id = auth.uid()) with check (coiffeur_id = auth.uid());
create policy "tx supprimer" on public.transformations
  for delete to authenticated using (coiffeur_id = auth.uid() or public.is_gerant());

-- Stockage des images : bucket public, noms de fichiers aléatoires
-- (impossible à deviner) pour que le client puisse ouvrir son lien.
insert into storage.buckets (id, name, public)
values ('visuels', 'visuels', true)
on conflict (id) do update set public = true;

drop policy if exists "visuels ajouter" on storage.objects;
drop policy if exists "visuels lire" on storage.objects;
drop policy if exists "visuels modifier" on storage.objects;
drop policy if exists "visuels supprimer" on storage.objects;
create policy "visuels ajouter" on storage.objects
  for insert to authenticated
  with check (bucket_id = 'visuels' and (storage.foldername(name))[1] = auth.uid()::text);
create policy "visuels lire" on storage.objects
  for select to authenticated
  using (bucket_id = 'visuels' and ((storage.foldername(name))[1] = auth.uid()::text or public.is_gerant()));
create policy "visuels modifier" on storage.objects
  for update to authenticated
  using (bucket_id = 'visuels' and (storage.foldername(name))[1] = auth.uid()::text)
  with check (bucket_id = 'visuels' and (storage.foldername(name))[1] = auth.uid()::text);
create policy "visuels supprimer" on storage.objects
  for delete to authenticated
  using (bucket_id = 'visuels' and ((storage.foldername(name))[1] = auth.uid()::text or public.is_gerant()));
