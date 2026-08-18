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
- `src/cli.ts` — analizza (e con `--fix` corregge) una cartella locale da terminale; `install-hook` installa il controllo pre-commit
- `src/precommit.ts` — motore del git hook: legge i file in staging, blocca il commit se trova un problema critico
- `src/mcp/server.ts` — server MCP (JSON-RPC su stdio, senza SDK esterni) che espone `analyze_code`, `fix_code` e `list_checks` a un agente AI
- `src/supabaseConfigChecks.ts` — legge uno snapshot (query di sola lettura, incollata dall'utente) della configurazione reale di un progetto Supabase e verifica RLS/policy/bucket davvero, non solo dedotti dal codice

### Server MCP

Claude Code e altri agenti AI possono collegarsi a JoJoX come strumento MCP, senza passare dal sito:

```bash
npm run mcp   # avvia il server MCP su stdio