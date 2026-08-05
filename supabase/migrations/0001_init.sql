-- JoJoX — schema iniziale
-- Profili utente, storico delle analisi, installazioni della GitHub App
-- e impostazioni per repository. RLS attiva ovunque: ogni utente vede
-- solo i propri dati.

create extension if not exists pgcrypto;

-- ---------------------------------------------------------------------
-- profiles: un profilo per ogni utente Supabase Auth, con il piano attivo
-- ---------------------------------------------------------------------
create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  plan text not null default 'free' check (plan in ('free', 'pro', 'team')),
  stripe_customer_id text,
  created_at timestamptz not null default now()
);

alter table public.profiles enable row level security;

create policy "users read their own profile"
  on public.profiles for select
  using (auth.uid() = id);

create policy "users update their own profile"
  on public.profiles for update
  using (auth.uid() = id);

-- Crea automaticamente un profilo "free" alla registrazione.
create function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = public
as $$
begin
  insert into public.profiles (id) values (new.id);
  return new;
end;
$$;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

-- ---------------------------------------------------------------------
-- analyses: storico delle analisi (manuali o via GitHub)
-- ---------------------------------------------------------------------
create table public.analyses (
  id uuid primary key default gen_random_uuid(),
  -- nullable: le analisi generate da un'installazione GitHub non ancora
  -- collegata a un account (es. un'organizzazione che installa l'app
  -- prima di registrarsi sul sito) non hanno subito un proprietario.
  user_id uuid references auth.users (id) on delete cascade,
  source text not null check (source in ('manual', 'github')),
  repo_full_name text,
  score int not null check (score >= 0 and score <= 100),
  summary jsonb not null,
  findings jsonb not null,
  created_at timestamptz not null default now()
);

alter table public.analyses enable row level security;

create policy "users read their own analyses"
  on public.analyses for select
  using (auth.uid() = user_id);

create policy "users insert their own analyses"
  on public.analyses for insert
  with check (auth.uid() = user_id);

create index analyses_user_id_created_at_idx
  on public.analyses (user_id, created_at desc);

-- ---------------------------------------------------------------------
-- github_installations: una riga per ogni installazione della GitHub App
-- ---------------------------------------------------------------------
create table public.github_installations (
  installation_id bigint primary key,
  account_login text not null,
  account_type text not null check (account_type in ('User', 'Organization')),
  installed_by uuid references auth.users (id) on delete set null,
  created_at timestamptz not null default now()
);

alter table public.github_installations enable row level security;

create policy "users read installations they created"
  on public.github_installations for select
  using (auth.uid() = installed_by);

-- ---------------------------------------------------------------------
-- github_repo_settings: impostazioni per singolo repository connesso
-- ---------------------------------------------------------------------
create table public.github_repo_settings (
  id uuid primary key default gen_random_uuid(),
  installation_id bigint not null references public.github_installations (installation_id) on delete cascade,
  repo_full_name text not null,
  block_on_critical boolean not null default true,
  block_on_high boolean not null default false,
  created_at timestamptz not null default now(),
  unique (installation_id, repo_full_name)
);

alter table public.github_repo_settings enable row level security;

create policy "users read settings for their own installations"
  on public.github_repo_settings for select
  using (
    installation_id in (
      select installation_id from public.github_installations
      where installed_by = auth.uid()
    )
  );

create policy "users update settings for their own installations"
  on public.github_repo_settings for update
  using (
    installation_id in (
      select installation_id from public.github_installations
      where installed_by = auth.uid()
    )
  );
