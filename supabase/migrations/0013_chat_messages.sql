-- JoJoX — log dei messaggi della chat che spiega i risultati di un'analisi
-- (punto 25a). Serve a due cose: imporre il limite giornaliero per piano
-- (DAILY_CHAT_MESSAGE_LIMIT in plan.ts) e tenere traccia dei costi reali
-- verso l'API Anthropic. Scritta solo dal backend con la service role key,
-- come repo_scan_state: nessuna policy, nessun accesso diretto dal client.
create table public.chat_messages (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  role text not null check (role in ('user', 'assistant')),
  content text not null,
  created_at timestamptz not null default now()
);

alter table public.chat_messages enable row level security;

create index chat_messages_user_id_created_at_idx
  on public.chat_messages (user_id, created_at desc);
