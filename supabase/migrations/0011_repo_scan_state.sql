-- JoJoX — Sentinella 24/7: stato dell'ultimo scan automatico di ogni
-- repository monitorato. Usato per confrontare un nuovo scan con quello
-- precedente e avvisare solo dei problemi *nuovi*, invece di far ripetere
-- ogni notte lo stesso avviso per un problema già noto e non ancora
-- risolto. Scritto solo dal cron interno del server con la service role
-- key: nessuna policy, come le altre tabelle che nessun utente legge
-- direttamente.
create table public.repo_scan_state (
  installation_id bigint not null references public.github_installations (installation_id) on delete cascade,
  repo_full_name text not null,
  finding_keys text[] not null default '{}',
  last_scanned_at timestamptz not null default now(),
  primary key (installation_id, repo_full_name)
);

alter table public.repo_scan_state enable row level security;
