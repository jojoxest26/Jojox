import type { Finding, FixExample } from "./types.js";

/**
 * Se un file caricato ha esattamente questo nome, non viene trattato come
 * codice sorgente: è lo snapshot della configurazione reale del progetto
 * Supabase (vedi SUPABASE_SNAPSHOT_QUERY), e viene analizzato a parte.
 */
export const SUPABASE_SNAPSHOT_FILENAME = "jojox-supabase-snapshot.json";

export interface SupabaseSchemaSnapshot {
  tables: { schema: string; name: string; rowsecurity: boolean }[];
  policies: { schema: string; table: string; name: string }[];
  buckets: { id: string; public: boolean }[];
}

/**
 * Query di sola lettura — solo cataloghi di sistema e storage.buckets,
 * nessuna scrittura possibile — da far girare nell'SQL Editor del proprio
 * progetto Supabase per ottenere lo snapshot reale della configurazione.
 */
export const SUPABASE_SNAPSHOT_QUERY = `select json_build_object(
  'tables', (
    select coalesce(json_agg(json_build_object(
      'schema', schemaname, 'name', tablename, 'rowsecurity', rowsecurity
    )), '[]'::json)
    from pg_tables where schemaname = 'public'
  ),
  'policies', (
    select coalesce(json_agg(json_build_object(
      'schema', schemaname, 'table', tablename, 'name', policyname
    )), '[]'::json)
    from pg_policies where schemaname = 'public'
  ),
  'buckets', (
    select coalesce(json_agg(json_build_object(
      'id', id, 'public', public
    )), '[]'::json)
    from storage.buckets
  )
) as jojox_snapshot;`;

function isValidSnapshot(value: unknown): value is SupabaseSchemaSnapshot {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return Array.isArray(v.tables) && Array.isArray(v.policies) && Array.isArray(v.buckets);
}

/**
 * Legge il contenuto incollato/caricato dall'utente. Supabase esporta il
 * risultato di una singola colonna (qui "jojox_snapshot") annidato sotto
 * quel nome quando si scarica una riga come JSON: accettiamo sia quella
 * forma sia lo snapshot diretto.
 */
export function parseSupabaseSnapshot(content: string): SupabaseSchemaSnapshot | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    return null;
  }
  if (isValidSnapshot(parsed)) return parsed;
  const nested = (parsed as Record<string, unknown> | null)?.jojox_snapshot;
  return isValidSnapshot(nested) ? nested : null;
}

function fixExample(before: string, after: string): FixExample {
  return { before, after };
}

/**
 * A differenza degli altri controlli (che leggono codice sorgente e quindi
 * possono solo dedurre cosa succede a runtime), questi leggono lo stato
 * vero del progetto Supabase: la confidenza sui fatti osservati è massima.
 */
export function supabaseConfigFindings(snapshot: SupabaseSchemaSnapshot): Finding[] {
  const findings: Finding[] = [];

  for (const table of snapshot.tables) {
    const label = `${table.schema}.${table.name}`;

    if (!table.rowsecurity) {
      findings.push({
        checkId: "supabase-live-rls-disabled",
        severity: "critical",
        confidence: "confirmed",
        title: "Row Level Security disattivata su una tabella reale del progetto",
        description:
          "Verificato collegandosi al vero progetto Supabase, non dedotto dal codice: questa tabella ha la Row Level Security disattivata. Chiunque abbia la chiave anon può leggere o scrivere tutte le righe, indipendentemente da cosa fa (o non fa) il codice dell'app.",
        file: label,
        line: 0,
        snippet: "rowsecurity: false",
        fix: fixExample(`-- ${label}: RLS disattivata`, `ALTER TABLE ${label} ENABLE ROW LEVEL SECURITY;`),
      });
      continue;
    }

    const hasPolicies = snapshot.policies.some((p) => p.schema === table.schema && p.table === table.name);
    if (!hasPolicies) {
      findings.push({
        checkId: "supabase-live-rls-no-policies",
        severity: "medium",
        confidence: "heuristic",
        title: "Row Level Security attiva ma senza nessuna policy",
        description:
          "La tabella ha RLS attiva ma zero policy definite: di fatto è bloccata per chiunque usi la chiave anon o sia un utente autenticato (solo la service_role può accedervi). Può essere voluto — verifica che sia così.",
        file: label,
        line: 0,
        snippet: "rowsecurity: true, policies: 0",
        fix: fixExample(
          `ALTER TABLE ${label} ENABLE ROW LEVEL SECURITY;\n-- nessuna policy definita`,
          `CREATE POLICY "owners only" ON ${label}\n  USING (auth.uid() = user_id);`
        ),
      });
    }
  }

  for (const bucket of snapshot.buckets) {
    if (bucket.public) {
      findings.push({
        checkId: "supabase-live-public-bucket",
        severity: "medium",
        confidence: "confirmed",
        title: "Bucket di storage pubblico nel progetto reale",
        description:
          "Verificato collegandosi al vero progetto Supabase: il bucket è configurato come pubblico. Se contiene file caricati dagli utenti, chiunque conosca — o indovini — il percorso può accedervi senza autenticazione.",
        file: `storage.${bucket.id}`,
        line: 0,
        snippet: "public: true",
        fix: fixExample(
          `update storage.buckets set public = true where id = '${bucket.id}';`,
          `update storage.buckets set public = false where id = '${bucket.id}';`
        ),
      });
    }
  }

  return findings;
}