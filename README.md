# JoJoX — motore, backend e sito

Sicurezza per codice scritto (anche) da AI: 21 controlli statici, punteggio 0-100 trasparente, esempio di correzione prima/dopo per ogni problema. Il motore è pattern matching puro (nessun LLM) — gira sia lato server sia nel browser, non solo in teoria: il sito lo importa direttamente per l'analisi in modalità ospite.

## Struttura

**Motore** (`src/`, riusabile server-side e client-side, senza I/O):
- `src/types.ts` — tipi condivisi (`Check`, `Finding`, `AnalysisResult`, ...)
- `src/util/scan.ts` — scansione riga per riga e redazione degli snippet (mai la riga intera)
- `src/checks/{critical,high,medium,low}.ts` — gli 8+5+6+2 controlli, uno per gravità
- `src/scoring.ts` — formula del punteggio, a rendimento decrescente per occorrenze ripetute dello stesso controllo
- `src/analyze.ts` — `analyzeFiles(files)`, il punto d'ingresso
- `src/autofix.ts` — `applyAutofixes(files)`, corregge in automatico quello che i singoli controlli sanno correggere
- `src/cli.ts` — analizza (e con `--fix` corregge) una cartella locale da terminale
- `src/mcp/server.ts` — server MCP (JSON-RPC su stdio, senza SDK esterni) che espone `analyze_code`, `fix_code` e `list_checks` a un agente AI
- `src/supabaseConfigChecks.ts` — legge uno snapshot (query di sola lettura, incollata dall'utente) della configurazione reale di un progetto Supabase e verifica RLS/policy/bucket davvero, non solo dedotti dal codice

**Backend** (`src/server/`):
- `src/server/app.ts` / `index.ts` — server Express, CORS ristretto a `ALLOWED_ORIGINS`
- `src/server/routes/analyze.ts` — `POST /api/analyze`, con limite mensile per il piano free e storico salvato per utenti autenticati
- `src/server/routes/analyses.ts` — `GET /api/analyses`, storico dell'utente
- `src/server/routes/waitlist.ts` — `POST /api/waitlist`
- `src/server/routes/webhooks/github.ts` — riceve i webhook della GitHub App, analizza le pull request, crea un check run, commenta con i risultati e apre una PR di correzione automatica quando può
- `src/server/github/` — autenticazione della GitHub App, verifica firma webhook, formattazione del commento/check run
- `src/server/auth/middleware.ts` — verifica del token Supabase
- `supabase/migrations/` — schema del database (profili, storico, installazioni GitHub, waitlist, analisi ospite), RLS attiva su ogni tabella

**Sito** (`web/`, Vite + React + TypeScript):
- Landing page, analisi client-side (drag&drop → `analyzeFiles` importato direttamente dal motore)
- Login via Supabase (magic link email), storico delle analisi per utenti loggati
- 1 analisi gratuita senza email (limite imposto dal server per IP), poi serve l'email per 5 analisi/mese gratis
- Bottone "Collega GitHub" verso l'installazione reale della GitHub App
- Elenco dei 21 controlli generato dai metadati veri dell'engine (`ALL_CHECKS`), sempre sincronizzato col codice

## Uso

```bash
npm install
npm test                                # 83 test: engine + backend
npm run cli -- ./path/al/progetto       # analizza una cartella locale
npm run cli -- ./path/al/progetto --fix # corregge in automatico quello che si può
npm run dev                             # backend in locale (richiede un .env, vedi .env.example)

cd web
npm install
npm run dev                       # sito in locale (richiede un .env, vedi web/.env.example)