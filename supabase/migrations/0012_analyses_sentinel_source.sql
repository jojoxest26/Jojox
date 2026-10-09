-- La Sentinella 24/7 (rescan automatico notturno) salva il proprio storico
-- con source = 'sentinel', distinto da un'analisi manuale, da un push su
-- GitHub o da un Full Site Audit — altrimenti sarebbe indistinguibile da
-- un'analisi manuale nello storico e nella dashboard del team.
alter table public.analyses drop constraint analyses_source_check;
alter table public.analyses add constraint analyses_source_check
  check (source in ('manual', 'github', 'audit', 'sentinel'));
