-- URL del webhook Slack (opzionale) a cui inviare un avviso quando JoJoX
-- blocca una pull request o propone correzioni automatiche. Un webhook per
-- installazione (account/organizzazione), non per singolo repository.
-- Scritto solo dal server (service role) dopo aver verificato che chi
-- chiama è davvero chi ha installato la GitHub App — stessa logica già in
-- uso per le altre tabelle, niente policy di scrittura via RLS.
alter table public.github_installations
  add column slack_webhook_url text;