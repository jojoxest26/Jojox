# JoJoX per VS Code

Controlla il codice mentre scrivi, direttamente nell'editor — stesso motore del sito jojox.it e del CLI, nessun LLM, nessun dato inviato fuori dal tuo computer.

## Sviluppo

```bash
npm install
npm run compile   # oppure: npm run watch, per ricompilare a ogni modifica
```

Poi, in VS Code:
1. Apri **questa cartella** (`vscode-extension/`) come cartella di lavoro (non l'intero repository)
2. Premi **F5** — si apre una nuova finestra "Extension Development Host" con l'estensione già attiva
3. In quella finestra, apri o crea un file con un problema di sicurezza (es. una chiave API scritta in chiaro) — dovresti vedere una sottolineatura rossa/gialla

Nessuna nuova dipendenza a runtime: il motore (`src/`, alla radice del repository) resta l'unica fonte di verità dei controlli, riusata così com'è.