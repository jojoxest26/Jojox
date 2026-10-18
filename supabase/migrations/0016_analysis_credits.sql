-- JoJoX — tetto mensile di analisi anche per Pro e Team (prima "illimitate":
-- un rischio concreto, dato che ogni push su un repository collegato genera
-- un'analisi automatica). Chi supera la quota mensile può comprare un
-- pacchetto extra (pagamento singolo) invece di restare bloccato fino al
-- mese successivo. Stesso schema "ledger + crediti monouso" di audit_credits,
-- ma un acquisto crea più crediti insieme (un pacchetto), non uno solo, quindi
-- serve una tabella separata per l'acquisto (dedup sul checkout Stripe) da
-- quella dei singoli crediti consumabili.

create table public.analysis_credit_purchases (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  stripe_checkout_session_id text not null unique,
  credits integer not null,
  created_at timestamptz not null default now()
);

alter table public.analysis_credit_purchases enable row level security;

create policy "users read their own analysis credit purchases"
  on public.analysis_credit_purchases for select
  using (auth.uid() = user_id);

create table public.analysis_credits (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  purchase_id uuid not null references public.analysis_credit_purchases (id) on delete cascade,
  status text not null default 'unused' check (status in ('unused', 'used')),
  created_at timestamptz not null default now(),
  used_at timestamptz
);

alter table public.analysis_credits enable row level security;

create policy "users read their own analysis credits"
  on public.analysis_credits for select
  using (auth.uid() = user_id);

create index analysis_credits_user_id_status_idx
  on public.analysis_credits (user_id, status);
