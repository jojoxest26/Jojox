import { describe, expect, it } from "vitest";
import { callTool, handleRequest, TOOLS } from "../../src/mcp/server.js";

describe("MCP server: handleRequest", () => {
  it("initialize risponde con le info del server", () => {
    const res = handleRequest({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05" } });
    expect(res).toMatchObject({
      jsonrpc: "2.0",
      id: 1,
      result: { protocolVersion: "2024-11-05", serverInfo: { name: "jojox" } },
    });
  });

  it("una notifica (senza id) non produce nessuna risposta", () => {
    const res = handleRequest({ jsonrpc: "2.0", method: "notifications/initialized" });
    expect(res).toBeUndefined();
  });

  it("tools/list elenca i 3 strumenti esposti", () => {
    const res = handleRequest({ jsonrpc: "2.0", id: 2, method: "tools/list" }) as any;
    expect(res.result.tools.map((t: { name: string }) => t.name)).toEqual(["analyze_code", "fix_code", "list_checks"]);
  });

  it("un metodo sconosciuto torna un errore JSON-RPC, non un'eccezione", () => {
    const res = handleRequest({ jsonrpc: "2.0", id: 3, method: "not/a/real/method" }) as any;
    expect(res.error.code).toBe(-32601);
  });

  it("tools/call con uno strumento inesistente torna isError:true invece di far cadere il processo", () => {
    const res = handleRequest({
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: { name: "does_not_exist", arguments: {} },
    }) as any;
    expect(res.result.isError).toBe(true);
  });

  it("tools/call su analyze_code trova un problema in codice vulnerabile", () => {
    const res = handleRequest({
      jsonrpc: "2.0",
      id: 5,
      method: "tools/call",
      params: {
        name: "analyze_code",
        arguments: { files: [{ path: "supabase/migrations/0001.sql", content: "ALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;" }] },
      },
    }) as any;
    const payload = JSON.parse(res.result.content[0].text);
    expect(payload.findings).toHaveLength(1);
    expect(payload.findings[0].checkId).toBe("missing-row-level-security");
  });

  it("tools/call su fix_code restituisce solo i file effettivamente cambiati", () => {
    const res = handleRequest({
      jsonrpc: "2.0",
      id: 6,
      method: "tools/call",
      params: {
        name: "fix_code",
        arguments: {
          files: [
            { path: "supabase/migrations/0001.sql", content: "ALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;" },
            { path: "src/clean.ts", content: "const x = 1" },
          ],
        },
      },
    }) as any;
    const payload = JSON.parse(res.result.content[0].text);
    expect(payload.filesChanged).toBe(1);
    expect(payload.files).toHaveLength(1);
    expect(payload.files[0].path).toBe("supabase/migrations/0001.sql");
    expect(payload.files[0].content).toContain("ENABLE ROW LEVEL SECURITY");
  });
});

describe("MCP server: callTool", () => {
  it("list_checks elenca tutti i 21 controlli", () => {
    const result = callTool("list_checks", {}) as unknown[];
    expect(result).toHaveLength(21);
  });

  it("analyze_code richiede il parametro 'files'", () => {
    expect(() => callTool("analyze_code", {})).toThrow(/files/);
  });

  it("uno strumento sconosciuto fa fallire callTool con un errore leggibile", () => {
    expect(() => callTool("nope", {})).toThrow(/Strumento sconosciuto/);
  });
});

describe("MCP server: TOOLS", () => {
  it("ogni strumento ha nome, descrizione e schema di input", () => {
    for (const tool of TOOLS) {
      expect(tool.name.length).toBeGreaterThan(0);
      expect(tool.description.length).toBeGreaterThan(0);
      expect(tool.inputSchema.type).toBe("object");
    }
  });
});