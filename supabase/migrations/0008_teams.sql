-- JoJoX — piano Team con seat multipli e dashboard condivisa.
-- Un account Team crea un gruppo ("team"); i membri invitati vedono gli
-- stessi repository collegati e lo stesso storico analisi di tutto il
-- gruppo, non solo i propri — è la differenza reale rispetto a Pro.
-- Come per le altre tabelle scritte solo dal server, nessuna policy di
-- insert/update/delete per gli utenti: solo la service role key scrive qui.

create table public.teams (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users (id) on delete cascade,
  name text not null default 'Team',
  created_at timestamptz not null default now(),
  unique (owner_id)
);

-- Una riga per ogni persona del team, invitata o già entrata.
-- user_id è nullo finché l'invito non viene accettato (nessun account
-- ancora collegato a quella email); joined_at nullo = invito in sospeso.
-- Creata subito dopo teams (non dopo le sue policy): la policy di teams
-- fa riferimento a questa tabella, quindi deve già esistere.
create table public.team_members (
  team_id uuid not null references public.teams (id) on delete cascade,
  user_id uuid references auth.users (id) on delete set null,
  email text not null,
  role text not null default 'member' check (role in ('owner', 'member')),
  invited_at timestamptz not null default now(),
  joined_at timestamptz,
  primary key (team_id, email)
);

alter table public.teams enable row level security;

create policy "members read their own team"
  on public.teams for select
  using (
    id in (
      select team_id from public.team_members
      where user_id = auth.uid() and joined_at is not null
    )
  );

alter table public.team_members enable row level security;

create policy "members read their own team roster"
  on public.team_members for select
  using (
    team_id in (
      select team_id from public.team_members
      where user_id = auth.uid() and joined_at is not null
    )
  );

create index team_members_user_id_idx on public.team_members (user_id);
create index team_members_email_idx on public.team_members (lower(email));