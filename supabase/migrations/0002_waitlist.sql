-- Lista d'attesa per le funzionalità "in arrivo" (badge auto-aggiornante,
-- correzioni automatiche via PR, ecc.). Nessuna lettura pubblica: solo il
-- server (service role) può leggerla, chiunque può iscriversi.

create table public.waitlist_emails (
  id uuid primary key default gen_random_uuid(),
  email text not null unique,
  created_at timestamptz not null default now()
);

alter table public.waitlist_emails enable row level security;

-- Nessuna policy di select/update per anon o authenticated: solo la
-- service role (che bypassa la RLS) può leggere gli iscritti.
create policy "anyone can join the waitlist"
  on public.waitlist_emails for insert
  with check (true);
