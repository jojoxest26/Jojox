-- Un Full Site Audit salvava lo storico con source = 'manual', identico a
-- una normale analisi manuale gratuita: nello storico (e nella dashboard
-- condivisa del team) i due finivano mescolati sotto la stessa etichetta,
-- senza modo di distinguere un audit pagato da un'analisi al volo.
alter table public.analyses drop constraint analyses_source_check;
alter table public.analyses add constraint analyses_source_check
  check (source in ('manual', 'github', 'audit'));