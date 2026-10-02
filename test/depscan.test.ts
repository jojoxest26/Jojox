import { afterEach, describe, expect, it, vi } from "vitest";
import { parseNpmLockfile, scanDependencies } from "../src/depscan.js";

afterEach(() => {
  vi.unstubAllGlobals();
});

const LOCKFILE_V3 = JSON.stringify({
  name: "demo",
  lockfileVersion: 3,
  packages: {
    "": { name: "demo" },
    "node_modules/lodash": { version: "4.17.11", resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.11.tgz" },
    "node_modules/@scope/pkg": { version: "1.2.3" },
    "node_modules/safe-dep/node_modules/lodash": { version: "4.17.21" },
  },
});

const LOCKFILE_V1 = JSON.stringify({
  name: "demo",
  lockfileVersion: 1,
  dependencies: {
    lodash: { version: "4.17.11" },
    express: {
      version: "4.21.0",
      dependencies: {
        "safe-nested": { version: "1.0.0" },
      },
    },
  },
});

describe("parseNpmLockfile", () => {
  it("legge un lockfile v2/v3 (formato 'packages' piatto)", () => {
    const deps = parseNpmLockfile(LOCKFILE_V3);
    expect(deps).toContainEqual({ name: "lodash", version: "4.17.11" });
    expect(deps).toContainEqual({ name: "@scope/pkg", version: "1.2.3" });
    expect(deps).toContainEqual({ name: "lodash", version: "4.17.21" });
  });

  it("legge un lockfile v1 (albero 'dependencies' annidato, incluse le transitive)", () => {
    const deps = parseNpmLockfile(LOCKFILE_V1);
    expect(deps).toContainEqual({ name: "lodash", version: "4.17.11" });
    expect(deps).toContainEqual({ name: "express", version: "4.21.0" });
    expect(deps).toContainEqual({ name: "safe-nested", version: "1.0.0" });
  });

  it("deduplica la stessa coppia nome+versione", () => {
    const content = JSON.stringify({
      packages: {
        "": {},
        "node_modules/a/node_modules/lodash": { version: "4.17.11" },
        "node_modules/lodash": { version: "4.17.11" },
      },
    });
    expect(parseNpmLockfile(content)).toHaveLength(1);
  });

  it("torna [] su JSON non valido invece di lanciare un'eccezione", () => {
    expect(parseNpmLockfile("{ non è json")).toEqual([]);
  });

  it("torna [] quando non ci sono né 'packages' né 'dependencies'", () => {
    expect(parseNpmLockfile(JSON.stringify({ name: "demo" }))).toEqual([]);
  });
});

describe("scanDependencies", () => {
  it("torna [] senza chiamare la rete quando non c'è un package-lock.json", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const result = await scanDependencies([{ path: "src/index.ts", content: "const x = 1" }]);

    expect(result).toEqual([]);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("torna [] quando OSV.dev non segnala vulnerabilità per nessuna dipendenza", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ results: [{}] }),
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await scanDependencies([{ path: "package-lock.json", content: LOCKFILE_V1 }]);

    expect(result).toEqual([]);
  });

  it("segnala una dipendenza vulnerabile con gravità, descrizione e versione corretta da OSV.dev", async () => {
    const content = JSON.stringify({
      packages: { "": {}, "node_modules/lodash": { version: "4.17.11" } },
    });

    const fetchMock = vi.fn(async (url: string) => {
      if (url.toString().includes("querybatch")) {
        return { ok: true, json: async () => ({ results: [{ vulns: [{ id: "GHSA-p6mc-m468-83gw" }] }] }) };
      }
      return {
        ok: true,
        json: async () => ({
          id: "GHSA-p6mc-m468-83gw",
          summary: "Prototype Pollution in lodash",
          database_specific: { severity: "HIGH" },
          affected: [
            {
              package: { name: "lodash", ecosystem: "npm" },
              ranges: [{ events: [{ introduced: "0" }, { fixed: "4.17.12" }] }],
            },
          ],
        }),
      };
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await scanDependencies([{ path: "package-lock.json", content }]);

    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject({
      checkId: "vulnerable-dependency",
      severity: "high",
      confidence: "confirmed",
      file: "package-lock.json",
      line: 1,
    });
    expect(result[0].title).toContain("lodash@4.17.11");
    expect(result[0].title).toContain("GHSA-p6mc-m468-83gw");
    expect(result[0].description).toBe("Prototype Pollution in lodash");
    expect(result[0].fix.after).toContain("4.17.12");
  });

  it("trova la riga esatta della versione nel package-lock.json invece di 'riga 1' generica", async () => {
    const content = [
      "{",
      '  "packages": {',
      '    "": {},',
      '    "node_modules/lodash": {',
      '      "version": "4.17.11",',
      '      "resolved": "https://registry.npmjs.org/lodash"',
      "    }",
      "  }",
      "}",
    ].join("\n");

    const fetchMock = vi.fn(async (url: string) => {
      if (url.toString().includes("querybatch")) {
        return { ok: true, json: async () => ({ results: [{ vulns: [{ id: "GHSA-test" }] }] }) };
      }
      return { ok: true, json: async () => ({ id: "GHSA-test", database_specific: { severity: "LOW" } }) };
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await scanDependencies([{ path: "package-lock.json", content }]);

    expect(result[0].line).toBe(5);
    expect(result[0].snippet).toBe('"version": "4.17.11",');
    expect(result[0].severity).toBe("low");
  });

  it("mappa correttamente ogni livello di gravità di OSV.dev, e usa 'high' quando manca", async () => {
    const severities = ["CRITICAL", "HIGH", "MODERATE", "LOW", undefined] as const;
    for (const dbSeverity of severities) {
      const content = JSON.stringify({ packages: { "": {}, "node_modules/pkg": { version: "1.0.0" } } });
      const fetchMock = vi.fn(async (url: string) => {
        if (url.toString().includes("querybatch")) {
          return { ok: true, json: async () => ({ results: [{ vulns: [{ id: "GHSA-x" }] }] }) };
        }
        return { ok: true, json: async () => ({ id: "GHSA-x", database_specific: dbSeverity ? { severity: dbSeverity } : {} }) };
      });
      vi.stubGlobal("fetch", fetchMock);

      const result = await scanDependencies([{ path: "package-lock.json", content }]);
      const expected = { CRITICAL: "critical", HIGH: "high", MODERATE: "medium", LOW: "low" }[dbSeverity ?? ""] ?? "high";
      expect(result[0].severity).toBe(expected);
    }
  });

  it("suggerisce un messaggio chiaro quando OSV.dev non indica nessuna versione corretta", async () => {
    const content = JSON.stringify({ packages: { "": {}, "node_modules/pkg": { version: "1.0.0" } } });
    const fetchMock = vi.fn(async (url: string) => {
      if (url.toString().includes("querybatch")) {
        return { ok: true, json: async () => ({ results: [{ vulns: [{ id: "GHSA-nofix" }] }] }) };
      }
      return { ok: true, json: async () => ({ id: "GHSA-nofix", affected: [] }) };
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await scanDependencies([{ path: "package-lock.json", content }]);
    expect(result[0].fix.after).toMatch(/nessuna versione corretta/i);
  });

  it("non lancia un'eccezione se la chiamata batch a OSV.dev fallisce — torna semplicemente []", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("network down")));

    const result = await scanDependencies([{ path: "package-lock.json", content: LOCKFILE_V1 }]);
    expect(result).toEqual([]);
  });

  it("ignora un singolo ID di vulnerabilità irraggiungibile senza perdere gli altri", async () => {
    const content = JSON.stringify({
      packages: {
        "": {},
        "node_modules/a": { version: "1.0.0" },
        "node_modules/b": { version: "2.0.0" },
      },
    });

    const fetchMock = vi.fn(async (url: string) => {
      const u = url.toString();
      if (u.includes("querybatch")) {
        return {
          ok: true,
          json: async () => ({ results: [{ vulns: [{ id: "GHSA-a" }] }, { vulns: [{ id: "GHSA-b" }] }] }),
        };
      }
      if (u.includes("GHSA-a")) throw new Error("network down");
      return { ok: true, json: async () => ({ id: "GHSA-b", database_specific: { severity: "LOW" } }) };
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await scanDependencies([{ path: "package-lock.json", content }]);
    expect(result).toHaveLength(1);
    expect(result[0].title).toContain("GHSA-b");
  });

  it("suddivide in più chiamate batch quando ci sono più di 100 dipendenze", async () => {
    const packages: Record<string, unknown> = { "": {} };
    for (let i = 0; i < 150; i++) {
      packages[`node_modules/pkg${i}`] = { version: "1.0.0" };
    }
    const content = JSON.stringify({ packages });

    const batchCalls: unknown[] = [];
    const fetchMock = vi.fn(async (url: string, init?: { body?: string }) => {
      if (url.toString().includes("querybatch")) {
        batchCalls.push(JSON.parse(init?.body ?? "{}"));
        return { ok: true, json: async () => ({ results: [] }) };
      }
      return { ok: true, json: async () => ({}) };
    });
    vi.stubGlobal("fetch", fetchMock);

    await scanDependencies([{ path: "package-lock.json", content }]);

    expect(batchCalls).toHaveLength(2);
    expect((batchCalls[0] as { queries: unknown[] }).queries).toHaveLength(100);
    expect((batchCalls[1] as { queries: unknown[] }).queries).toHaveLength(50);
  });

  it("ignora un package-lock.json dentro node_modules", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const result = await scanDependencies([
      { path: "node_modules/some-pkg/package-lock.json", content: LOCKFILE_V1 },
    ]);

    expect(result).toEqual([]);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});