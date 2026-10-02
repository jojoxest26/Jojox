import { afterEach, describe, expect, it, vi } from "vitest";
import { parseNpmLockfile, parseRequirementsTxt, scanDependencies } from "../src/depscan.js";

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

describe("parseRequirementsTxt", () => {
  it("legge le dipendenze pinnate con ==", () => {
    const content = ["flask==2.0.1", "requests==2.25.1"].join("\n");
    expect(parseRequirementsTxt(content)).toEqual([
      { name: "flask", version: "2.0.1" },
      { name: "requests", version: "2.25.1" },
    ]);
  });

  it("ignora le dipendenze non pinnate (range o senza versione)", () => {
    const content = ["django>=4.0", "django~=4.0.1", "numpy"].join("\n");
    expect(parseRequirementsTxt(content)).toEqual([]);
  });

  it("gestisce extra, marker d'ambiente e commenti", () => {
    const content = [
      'requests[security]==2.25.1; python_version >= "3.8"  # per TLS',
      "# questo è solo un commento",
      "",
    ].join("\n");
    expect(parseRequirementsTxt(content)).toEqual([{ name: "requests", version: "2.25.1" }]);
  });

  it("ignora le righe direttiva (-r, -e, --hash)", () => {
    const content = ["-r requirements-dev.txt", "-e .", "--hash=sha256:abc", "flask==2.0.1"].join("\n");
    expect(parseRequirementsTxt(content)).toEqual([{ name: "flask", version: "2.0.1" }]);
  });

  it("deduplica la stessa coppia nome+versione", () => {
    const content = ["flask==2.0.1", "flask==2.0.1"].join("\n");
    expect(parseRequirementsTxt(content)).toHaveLength(1);
  });
});

describe("scanDependencies — Python (requirements.txt)", () => {
  it("segnala una dipendenza Python vulnerabile, interrogando OSV.dev con l'ecosistema PyPI", async () => {
    const content = "flask==0.12\n";
    const batchCalls: unknown[] = [];

    const fetchMock = vi.fn(async (url: string, init?: { body?: string }) => {
      if (url.toString().includes("querybatch")) {
        batchCalls.push(JSON.parse(init?.body ?? "{}"));
        return { ok: true, json: async () => ({ results: [{ vulns: [{ id: "PYSEC-2019-1" }] }] }) };
      }
      return {
        ok: true,
        json: async () => ({
          id: "PYSEC-2019-1",
          summary: "Improper Input Validation in Flask",
          database_specific: { severity: "MODERATE" },
          affected: [{ package: { name: "flask", ecosystem: "PyPI" }, ranges: [{ events: [{ fixed: "0.12.3" }] }] }],
        }),
      };
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await scanDependencies([{ path: "requirements.txt", content }]);

    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject({ checkId: "vulnerable-dependency", severity: "medium", file: "requirements.txt", line: 1 });
    expect(result[0].title).toContain("flask@0.12");
    expect(result[0].fix.before).toBe("flask==0.12");
    expect(result[0].fix.after).toBe("flask==0.12.3");
    expect((batchCalls[0] as { queries: { package: { name: string; ecosystem: string } }[] }).queries[0]).toEqual({
      package: { name: "flask", ecosystem: "PyPI" },
      version: "0.12",
    });
  });

  it("normalizza il nome del pacchetto (PEP 503) solo per interrogare OSV.dev, non nel testo mostrato", async () => {
    const content = "Flask-SQLAlchemy==2.4.0\n";
    const batchCalls: unknown[] = [];

    const fetchMock = vi.fn(async (url: string, init?: { body?: string }) => {
      if (url.toString().includes("querybatch")) {
        batchCalls.push(JSON.parse(init?.body ?? "{}"));
        return { ok: true, json: async () => ({ results: [{}] }) };
      }
      return { ok: true, json: async () => ({}) };
    });
    vi.stubGlobal("fetch", fetchMock);

    await scanDependencies([{ path: "requirements.txt", content }]);

    expect((batchCalls[0] as { queries: { package: { name: string } }[] }).queries[0].package.name).toBe("flask-sqlalchemy");
  });

  it("trova la riga esatta nel requirements.txt invece di 'riga 1' generica", async () => {
    const content = ["# commento", "requests==2.25.1", "flask==0.12"].join("\n");

    const fetchMock = vi.fn(async (url: string) => {
      if (url.toString().includes("querybatch")) {
        return { ok: true, json: async () => ({ results: [{}, { vulns: [{ id: "PYSEC-x" }] }] }) };
      }
      return { ok: true, json: async () => ({ id: "PYSEC-x", database_specific: { severity: "LOW" } }) };
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await scanDependencies([{ path: "requirements.txt", content }]);
    expect(result[0].line).toBe(3);
    expect(result[0].snippet).toBe("flask==0.12");
  });

  it("torna [] senza chiamare la rete quando non c'è né un package-lock.json né un requirements.txt", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const result = await scanDependencies([{ path: "src/app.py", content: "print('ciao')" }]);

    expect(result).toEqual([]);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("scansiona entrambi i manifest insieme in un progetto full-stack (npm + Python)", async () => {
    const npmContent = JSON.stringify({ packages: { "": {}, "node_modules/lodash": { version: "4.17.11" } } });
    const pyContent = "flask==0.12\n";

    const fetchMock = vi.fn(async (url: string, init?: { body?: string }) => {
      const u = url.toString();
      if (u.includes("querybatch")) {
        const body = JSON.parse(init?.body ?? "{}") as { queries: { package: { ecosystem: string } }[] };
        const ecosystem = body.queries[0]?.package.ecosystem;
        if (ecosystem === "npm") return { ok: true, json: async () => ({ results: [{ vulns: [{ id: "GHSA-npm" }] }] }) };
        return { ok: true, json: async () => ({ results: [{ vulns: [{ id: "PYSEC-py" }] }] }) };
      }
      if (u.includes("GHSA-npm")) return { ok: true, json: async () => ({ id: "GHSA-npm", database_specific: { severity: "HIGH" } }) };
      return { ok: true, json: async () => ({ id: "PYSEC-py", database_specific: { severity: "LOW" } }) };
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await scanDependencies([
      { path: "package-lock.json", content: npmContent },
      { path: "requirements.txt", content: pyContent },
    ]);

    expect(result.map((f) => f.file).sort()).toEqual(["package-lock.json", "requirements.txt"]);
  });
});