-- JoJoX — la cronologia della chat a volte tornava con domanda e risposta
-- scambiate di ordine. Ogni scambio si salva con UN SOLO insert a due
-- righe (domanda + risposta), e dentro un solo statement SQL Postgres dà
-- a entrambe le righe lo STESSO valore di now() — il timestamp resta
-- congelato per tutta la durata dello statement, quindi created_at da
-- solo non distingue chi viene prima tra le due. Una colonna che si
-- autoincrementa a ogni riga inserita toglie l'ambiguità in modo certo.
alter table public.chat_messages add column seq bigserial;

-- Non tocca l'indice su (user_id, created_at): serve ancora al conteggio
-- del limite giornaliero in src/server/routes/chat.ts, che filtra per
-- intervallo di date e non ha bisogno dell'ordine esatto tra due righe
-- con lo stesso timestamp.
create index chat_messages_user_id_seq_idx
  on public.chat_messages (user_id, seq);
