-- JoJoX — Full Site Audit Aziendale: distingue i crediti acquistati al
-- prezzo consumer (99€, report standard) da quelli acquistati al prezzo
-- business (990€, report con mappatura NIS2/DORA) — stessa tabella, stesso
-- flusso di analisi, solo il report scaricato cambia in base al valore qui.
alter table public.audit_credits
  add column tier text not null default 'standard' check (tier in ('standard', 'business'));
