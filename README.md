# JoJoX — motore, backend e sito

Sicurezza per codice scritto (anche) da AI: 21 controlli statici, punteggio 0-100 trasparente, esempio di correzione prima/dopo per ogni problema. Il motore è pattern matching puro (nessun LLM) — gira sia lato server sia nel browser, non solo in teoria: il sito lo importa direttamente per l'analisi in modalità ospite.

## Struttura

**Motore** (`src/`, riusabile server-side e client-side, senza I/O):
- `src/types.ts` — tipi condivisi (`Check`, `Finding`, `AnalysisResult`, ...)
- `src/util/scan.ts` — scansione riga per riga e redazione degli snippet (mai la riga intera)
- `src/checks/{critical,high,medium,low}.ts` — gli 8+5+6+2 controlli, uno per gravità
- `src/scoring.ts` — formula del punteggio, a rendimento decrescente per occorrenze ripetute dello stesso controllo
- `src/analyze.ts` — `analyzeFiles(files)`, il punto d'ingresso
- `src/cli.ts` — analizza una cartella locale da terminale

**Backend** (`src/server/`):
- `src/server/app.ts` / `index.ts` — server Express, CORS ristretto a `ALLOWED_ORIGINS`
- `src/server/routes/analyze.ts` — `POST /api/analyze`, con limite mensile per il piano free e storico salvato per utenti autenticati
- `src/server/routes/analyses.ts` — `GET /api/analyses`, storico dell'utente
- `src/server/routes/waitlist.ts` — `POST /api/waitlist`
- `src/server/routes/webhooks/github.ts` — riceve i webhook della GitHub App, analizza le pull request, crea un check run e commenta con i risultati
- `src/server/github/` — autenticazione della GitHub App, verifica firma webhook, formattazione del commento/check run
- `src/server/auth/middleware.ts` — verifica del token Supabase
- `supabase/migrations/` — schema del database (profili, storico, installazioni GitHub, waitlist), RLS attiva su ogni tabella

**Sito** (`web/`, Vite + React + TypeScript):
- Landing page, analisi client-side (drag&drop → `analyzeFiles` importato direttamente dal motore, zero chiamate di rete in modalità ospite)
- Login via Supabase (magic link email), storico delle analisi per utenti loggati
- Bottone "Collega GitHub" verso l'installazione reale della GitHub App
- Elenco dei 21 controlli generato dai metadati veri dell'engine (`ALL_CHECKS`), sempre sincronizzato col codice

## Uso

```bash
npm install
npm test                          # 72 test: engine + backend
npm run cli -- ./path/al/progetto # analizza una cartella locale
npm run dev                       # backend in locale (richiede un .env, vedi .env.example)

cd web
npm install
npm run dev                       # sito in locale (richiede un .env, vedi web/.env.example)
```

## Punteggio

Si parte da 100. Ogni controllo attivato sottrae punti in base alla gravità (critico 25, alto 12, medio 6, basso 3). Più occorrenze dello stesso controllo pesano di più ma con rendimento decrescente — tendono asintoticamente a 2 volte il peso base, non azzerano il punteggio da sole. Formula in `src/scoring.ts`.

## Deploy

Vedi **[SETUP.md](./SETUP.md)** per la procedura completa: Supabase, GitHub App, Railway (backend) e Vercel (sito).

## Prossimi passi

Non ancora costruiti (deliberatamente rimandati a dopo il primo cliente): pagamenti Stripe automatici, gestione multi-seat per i piani Team, badge auto-aggiornante nel README, CLI/MCP server standalone.
