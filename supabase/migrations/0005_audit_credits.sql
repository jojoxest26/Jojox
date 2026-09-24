-- JoJoX — Full Site Audit: crediti acquistati una tantum (pagamento singolo,
-- non abbonamento). Ogni riga rappresenta un audit pagato, usato una sola
-- volta. Nessuna policy di insert/update per gli utenti: solo il server
-- (webhook Stripe, endpoint di analisi) scrive qui, con la service role key.

create table public.audit_credits (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  status text not null default 'unused' check (status in ('unused', 'used')),
  stripe_checkout_session_id text,
  created_at timestamptz not null default now(),
  used_at timestamptz
);

alter table public.audit_credits enable row level security;

create policy "users read their own audit credits"
  on public.audit_credits for select
  using (auth.uid() = user_id);

create index audit_credits_user_id_status_idx
  on public.audit_credits (user_id, status);