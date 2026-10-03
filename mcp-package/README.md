# jojox-mcp

Server MCP di [JoJoX](https://jojox.it): gli stessi 40 controlli di sicurezza del sito, via pattern matching deterministico — nessun LLM nel motore, nessun codice inviato fuori dal tuo editor.

## Uso

Aggiungi al `.mcp.json` del tuo progetto (Claude Code) o alla configurazione MCP di Claude Desktop/Cursor:

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

Nessuna installazione manuale, nessun percorso locale da configurare.

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
