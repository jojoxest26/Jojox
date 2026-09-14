#!/usr/bin/env node
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { analyzeFiles, applyAutofixes } from "../analyze.js";
import { ALL_CHECKS } from "../checks/index.js";
import type { SourceFile } from "../types.js";

/**
 * Server MCP di JoJoX: espone il motore di analisi/correzione come strumenti
 * richiamabili da un agente AI (Claude Code, Claude Desktop, ecc.).
 *
 * Implementato a mano, senza l'SDK ufficiale @modelcontextprotocol/sdk: il
 * protocollo è solo JSON-RPC 2.0 su stdin/stdout, un messaggio per riga, e
 * qui serve solo un sottoinsieme minimo (initialize, tools/list, tools/call)
 * — non vale la pena aggiungere una dipendenza per questo.
 */

const SERVER_NAME = "jojox";
const SERVER_VERSION = "0.1.0";

interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: string | number;
  method: string;
  params?: Record<string, unknown>;
}

const FILES_SCHEMA = {
  type: "object",
  properties: {
    files: {
      type: "array",
      items: {
        type: "object",
        properties: {
          path: { type: "string" },
          content: { type: "string" },
        },
        required: ["path", "content"],
      },
    },
  },
  required: ["files"],
} as const;

export const TOOLS = [
  {
    name: "analyze_code",
    description:
      "Analizza dei file sorgente con i 21 controlli di sicurezza di JoJoX (pattern matching, nessun LLM) e restituisce punteggio da 0 a 100 e problemi trovati.",
    inputSchema: FILES_SCHEMA,
  },
  {
    name: "fix_code",
    description:
      "Applica le correzioni automatiche di JoJoX ai file forniti (le stesse regole usate dall'analisi) e restituisce solo i file effettivamente cambiati.",
    inputSchema: FILES_SCHEMA,
  },
  {
    name: "list_checks",
    description: "Elenca i 21 controlli di sicurezza di JoJoX, con gravità e se hanno una correzione automatica.",
    inputSchema: { type: "object", properties: {} },
  },
] as const;

function parseFiles(args: unknown): SourceFile[] {
  const files = (args as { files?: unknown } | undefined)?.files;
  if (!Array.isArray(files)) throw new Error("Parametro 'files' mancante o non è un array");
  return files.map((f) => {
    const path = (f as { path?: unknown } | null)?.path;
    const content = (f as { content?: unknown } | null)?.content;
    if (typeof path !== "string" || typeof content !== "string") {
      throw new Error("Ogni elemento di 'files' deve avere 'path' e 'content' come stringhe");
    }
    return { path, content };
  });
}

export function callTool(name: string, args: unknown): unknown {
  switch (name) {
    case "analyze_code":
      return analyzeFiles(parseFiles(args));
    case "fix_code": {
      const files = parseFiles(args);
      const autofix = applyAutofixes(files);
      const changed = files
        .map((original, i) => ({ original, fixed: autofix.files[i] }))
        .filter(({ original, fixed }) => fixed.content !== original.content)
        .map(({ fixed }) => fixed);
      return {
        files: changed,
        filesChanged: autofix.filesChanged,
        fixedCheckIds: [...autofix.fixedCheckIds],
        manualCheckIds: [...autofix.manualCheckIds],
      };
    }
    case "list_checks":
      return ALL_CHECKS.map((c) => ({
        id: c.id,
        severity: c.severity,
        confidence: c.confidence,
        title: c.title,
        hasAutofix: Boolean(c.autofix),
      }));
    default:
      throw new Error(`Strumento sconosciuto: ${name}`);
  }
}

/**
 * Elabora una singola richiesta JSON-RPC e restituisce il messaggio di risposta
 * da inviare, oppure `undefined` per una notifica (nessuna risposta prevista).
 * Non scrive mai direttamente su stdout: lo fa solo chi la chiama, così questa
 * funzione resta testabile senza avviare un vero processo.
 */
export function handleRequest(req: JsonRpcRequest): Record<string, unknown> | undefined {
  const { id, method, params } = req;
  const isNotification = id === undefined;

  try {
    switch (method) {
      case "initialize": {
        const protocolVersion = (params as { protocolVersion?: string } | undefined)?.protocolVersion ?? "2024-11-05";
        if (isNotification) return undefined;
        return {
          jsonrpc: "2.0",
          id,
          result: {
            protocolVersion,
            capabilities: { tools: {} },
            serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
          },
        };
      }
      case "notifications/initialized":
      case "ping":
        return isNotification ? undefined : { jsonrpc: "2.0", id, result: {} };
      case "tools/list":
        return isNotification ? undefined : { jsonrpc: "2.0", id, result: { tools: TOOLS } };
      case "tools/call": {
        const { name, arguments: args } = (params ?? {}) as { name?: string; arguments?: unknown };
        if (typeof name !== "string") throw new Error("Parametro 'name' mancante");
        const result = callTool(name, args);
        if (isNotification) return undefined;
        return {
          jsonrpc: "2.0",
          id,
          result: { content: [{ type: "text", text: JSON.stringify(result, null, 2) }], isError: false },
        };
      }
      default:
        return isNotification
          ? undefined
          : { jsonrpc: "2.0", id, error: { code: -32601, message: `Metodo sconosciuto: ${method}` } };
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (isNotification) return undefined;
    if (method === "tools/call") {
      return { jsonrpc: "2.0", id, result: { content: [{ type: "text", text: message }], isError: true } };
    }
    return { jsonrpc: "2.0", id, error: { code: -32603, message } };
  }
}

function send(message: Record<string, unknown>): void {
  process.stdout.write(`${JSON.stringify(message)}\n`);
}

/** Avvia il ciclo che legge richieste JSON-RPC da stdin, una per riga, e risponde su stdout. */
function startStdioServer(): void {
  const rl = createInterface({ input: process.stdin });
  rl.on("line", (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    let req: JsonRpcRequest;
    try {
      req = JSON.parse(trimmed);
    } catch {
      send({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "JSON non valido" } });
      return;
    }
    const response = handleRequest(req);
    if (response) send(response);
  });
}

// Avvia il server solo quando questo file viene eseguito direttamente (`npm run mcp`),
// non quando viene importato — ad esempio dai test, che vogliono solo le funzioni pure.
const isMainModule = process.argv[1] === fileURLToPath(import.meta.url);
if (isMainModule) startStdioServer();