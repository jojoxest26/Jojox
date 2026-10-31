-- JoJoX — Full Site Audit: sblocca la Revisione AI aggiuntiva per chi ha
-- appena pagato un audit (Standard o Business), anche se è sul piano Free,
-- senza aprire un accesso illimitato — una sola esecuzione per credito,
-- tracciata qui invece che nel limite giornaliero di ai_insight_runs
-- (pensato per gli abbonati Pro/Team, non per un acquisto una tantum).
alter table public.audit_credits
  add column ai_insight_used boolean not null default false;
