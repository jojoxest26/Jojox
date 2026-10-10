# jojox-mcp

Server MCP di [JoJoX](https://jojox.it): 49 controlli di sicurezza per codice generato (anche) da AI — pattern matching deterministico, **nessun LLM nel motore**.

**L'analisi avviene interamente in locale.** `jojox-mcp` gira come processo sul tuo computer, parla con il tuo agente via stdio: il codice che analizzi non viene mai inviato a JoJoX né a terzi, nessuna chiamata di rete nei tool `analyze_code` e `fix_code`. Per uno strumento di sicurezza, è una garanzia, non solo una comodità.

## Uso con Claude Code

Aggiungi al `.mcp.json` del progetto (o a quello globale):

```json
{
  "mcpServers": {
    "jojox": {
      "command": "npx",
      "args": ["-y", "jojox-mcp"]
    }
  }
}
```

## Uso con Cursor

Stessa configurazione, nel file `.cursor/mcp.json` del progetto (o in quello globale, `~/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "jojox": {
      "command": "npx",
      "args": ["-y", "jojox-mcp"]
    }
  }
}
```

## Uso con Claude Desktop

Stessa voce nel file di configurazione dell'app (Impostazioni → Sviluppatore → Modifica configurazione).

In tutti i casi: nessuna installazione manuale, nessun percorso locale da configurare, nessuna registrazione. Il tuo agente avvia `jojox-mcp` da solo al bisogno.

## Cosa controlla

49 controlli deterministici su JavaScript/TypeScript, Python, Go, Java, PHP e SQL/Supabase — chiavi e credenziali scritte nel codice, SQL/NoSQL/command/header injection, path traversal, SSRF, XSS, CSRF, IDOR, CORS permissivo, hashing debole, redirect aperti, controlli IaC su Dockerfile/Kubernetes/Terraform, e altro. Elenco completo e aggiornato, con gravità e confidenza di ognuno: [jojox.it](https://jojox.it).

## Strumenti esposti

- `analyze_code` — analizza dei file e restituisce punteggio (0-100) e problemi trovati.
- `fix_code` — applica le correzioni automatiche disponibili e restituisce solo i file cambiati.
- `list_checks` — elenca tutti i controlli, con gravità e se hanno una correzione automatica.

## Sviluppo

Questo package è un wrapper pubblicabile attorno al motore di analisi di JoJoX (cartella `src/` del repository principale). Per compilarlo:

```bash
npm install
npm run build
```

Il codice sorgente del motore resta nel repository principale (`jojoxest26/jojox`); questo package ne distribuisce solo la build compilata.

## Link

- Sito: [jojox.it](https://jojox.it)
- Codice sorgente del motore: [github.com/jojoxest26/Jojox](https://github.com/jojoxest26/Jojox)
- Segnalazione vulnerabilità: [jojox.it/sicurezza](https://jojox.it/sicurezza)
