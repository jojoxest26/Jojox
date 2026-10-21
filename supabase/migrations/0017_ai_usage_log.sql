-- JoJoX — log dei token reali consumati da ogni chiamata a pagamento
-- all'API Anthropic (chat e revisione AI aggiuntiva), punto 18 quater della
-- roadmap: senza questo non misuriamo mai quanto costa davvero un
-- utente Pro/Team contro quanto incassiamo da lui, e rischiamo un margine
-- negativo senza saperlo finché il tetto giornaliero attuale (DAILY_CHAT_
-- MESSAGE_LIMIT / DAILY_AI_INSIGHT_LIMIT in plan.ts) non basta più a
-- contenere i costi. Scritta solo dal backend con la service role key,
-- come chat_messages e ai_insight_runs: nessuna policy, nessun accesso
-- diretto dal client.
create table public.ai_usage_log (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  -- "chat_general" | "chat_findings" | "ai_insight" — stessa chiamata ma
  -- modello e costo diversi (vedi buildSystemPrompt/isGeneralMode in
  -- chat.ts), serve a scomporre il costo per tipo di uso, non solo per piano.
  route text not null,
  model text not null,
  input_tokens integer not null,
  output_tokens integer not null,
  created_at timestamptz not null default now()
);

alter table public.ai_usage_log enable row level security;

create index ai_usage_log_user_id_created_at_idx
  on public.ai_usage_log (user_id, created_at desc);
