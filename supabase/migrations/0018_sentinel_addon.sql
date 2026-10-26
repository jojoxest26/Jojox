-- JoJoX — "Controllo h24 da solo" per le aziende: monitoraggio continuo
-- venduto come abbonamento a sé, indipendente dal piano (plan). Un account
-- può restare "free" per il resto (nessuna analisi extra, nessuna chat) e
-- avere comunque questo addon attivo, che alza il tetto di repository
-- monitorati dalla Sentinella 24/7 da 1 (incluso gratis in Free) a 25.
alter table public.profiles
  add column sentinel_addon_active boolean not null default false;
