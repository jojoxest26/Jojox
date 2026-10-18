-- JoJoX — traccia le esecuzioni della revisione AI aggiuntiva (punto 14:
-- livello AI separato dai 55 controlli deterministici, per bug di logica
-- come race condition ed errori nei controlli di autorizzazione). Serve a
-- imporre il limite giornaliero per piano (DAILY_AI_INSIGHT_LIMIT in
-- plan.ts), esattamente come chat_messages fa per la chat. Scritta solo
-- dal backend con la service role key: nessuna policy, nessun accesso
-- diretto dal client.
create table public.ai_insight_runs (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  created_at timestamptz not null default now()
);

alter table public.ai_insight_runs enable row level security;

create index ai_insight_runs_user_id_created_at_idx
  on public.ai_insight_runs (user_id, created_at desc);
