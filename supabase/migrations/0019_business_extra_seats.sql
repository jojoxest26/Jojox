-- JoJoX — posti extra per il piano Business, oltre i 25 inclusi
-- (50€/mese a persona, venduti come riga a parte sull'abbonamento — vedi
-- stripe/plans.ts). Il trigger dei posti (migrazione 0010) deve conoscere
-- sia il piano del proprietario (Team = 5 posti, Business = 25 + extra)
-- sia quanti posti extra ha comprato, quindi la colonna vive qui e la
-- funzione del trigger viene sostituita per leggerla.
alter table public.teams
  add column extra_seats integer not null default 0;

create or replace function public.enforce_team_seat_limit()
returns trigger as $$
declare
  owner_plan text;
  base_cap integer;
  extra integer;
begin
  perform pg_advisory_xact_lock(hashtext(new.team_id::text));

  select p.plan, t.extra_seats into owner_plan, extra
  from public.teams t
  join public.profiles p on p.id = t.owner_id
  where t.id = new.team_id;

  base_cap := case when owner_plan = 'business' then 25 else 5 end;

  if (select count(*) from public.team_members where team_id = new.team_id) >= base_cap + coalesce(extra, 0) then
    raise exception 'team seat limit reached';
  end if;

  return new;
end;
$$ language plpgsql;
