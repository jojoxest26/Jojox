-- Il limite di 5 posti per team era controllato solo lato applicazione
-- (leggi il conteggio, poi scrivi se sotto il limite): due inviti inviati
-- nello stesso istante potrebbero entrambi leggere "4 posti occupati" prima
-- che l'altro scriva, superando il limite. Un trigger a livello di database,
-- eseguito dentro la stessa transazione dell'insert, chiude la finestra:
-- il lock (per team_id) serializza gli insert concorrenti sullo stesso team,
-- così il conteggio letto dal secondo insert include già il primo.
create or replace function public.enforce_team_seat_limit()
returns trigger as $$
begin
  perform pg_advisory_xact_lock(hashtext(new.team_id::text));

  if (select count(*) from public.team_members where team_id = new.team_id) >= 5 then
    raise exception 'team seat limit reached';
  end if;

  return new;
end;
$$ language plpgsql;

create trigger team_members_seat_limit
  before insert on public.team_members
  for each row
  execute function public.enforce_team_seat_limit();