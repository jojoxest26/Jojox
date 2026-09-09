-- Rimuove github_repo_settings: creata per permettere di scegliere quando
-- bloccare una pull request (block_on_critical / block_on_high), ma il
-- codice del webhook GitHub non l'ha mai letta — la regola è sempre stata
-- fissa (blocca su critico o alto). Tabella morta, mai usata da nessuna
-- rotta o interfaccia: nessun dato reale da preservare.

drop table if exists public.github_repo_settings;
