-- JoJoX — corregge una vulnerabilità reale trovata dalla Revisione AI: la
-- rotta /api/github/installations/:id/claim rivendicava qualunque
-- installazione GitHub App non ancora collegata, verificando solo "è
-- libera?" e mai "sei davvero tu che l'hai installata?". L'installation_id
-- di GitHub è un intero piccolo e facile da indovinare — chiunque fosse
-- loggato poteva rivendicare l'installazione di un'altra persona visitando
-- jojox.it/?installation_id=<numero indovinato>, prendendosi accesso ai
-- suoi repository collegati (e, con un Full Site Audit, la possibilità di
-- aprire Pull Request sul suo repository reale).
--
-- Questa tabella tiene un token "state" monouso, generato lato server solo
-- per l'utente che clicca "Connetti GitHub" e passato a GitHub nell'URL di
-- installazione — GitHub lo restituisce intatto nel redirect finale.
-- /claim ora richiede questo state, lo consuma una sola volta, e verifica
-- che appartenga davvero all'utente che sta chiamando: niente più
-- rivendicazioni di installazioni altrui.
create table public.github_install_states (
  state uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  created_at timestamptz not null default now()
);

alter table public.github_install_states enable row level security;

-- Nessuna policy di insert/select/delete per gli utenti: solo il server
-- (service role key) legge e scrive qui, come audit_credits.
