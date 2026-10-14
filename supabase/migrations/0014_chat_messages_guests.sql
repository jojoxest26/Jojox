-- JoJoX — la chat "Chiedi a JoJoX" ora risponde anche a chi non ha fatto
-- login (domande generali sul prodotto, non legate a un'analisi, aperte
-- dal bottone nell'hero). Per quei messaggi tracciamo l'IP invece
-- dell'utente, per applicare lo stesso tipo di limite giornaliero usato
-- già per gli utenti loggati — senza barriera, un bottone pubblico
-- sarebbe un invito aperto a far girare a vuoto una chiamata a pagamento.
alter table public.chat_messages alter column user_id drop not null;
alter table public.chat_messages add column ip_address inet;

alter table public.chat_messages
  add constraint chat_messages_identity_check
  check (user_id is not null or ip_address is not null);

create index chat_messages_ip_address_created_at_idx
  on public.chat_messages (ip_address, created_at desc)
  where ip_address is not null;
