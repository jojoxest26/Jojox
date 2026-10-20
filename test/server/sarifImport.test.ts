import { describe, expect, it } from "vitest";
import { parseSarif } from "../../src/server/routes/sarifImport.js";

function sarif(overrides: Record<string, unknown> = {}) {
  return {
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name: "Snyk Code", rules: [] } },
        results: [],
      },
    ],
    ...overrides,
  };
}

describe("parseSarif", () => {
  it("segnala errore se manca l'elenco runs", () => {
    const result = parseSarif({ version: "2.1.0" });
    expect(result).toEqual({ errorCode: "invalid_sarif" });
  });

  it("segnala errore su un documento che non è un oggetto", () => {
    expect(parseSarif(null)).toEqual({ errorCode: "invalid_sarif" });
    expect(parseSarif("stringa")).toEqual({ errorCode: "invalid_sarif" });
    expect(parseSarif([])).toEqual({ errorCode: "invalid_sarif" });
  });

  it("riconosce il nome dello strumento dal driver", () => {
    const result = parseSarif(sarif());
    expect(result).not.toHaveProperty("error");
    expect((result as { toolName: string | null }).toolName).toBe("Snyk Code");
  });

  it("torna toolName null quando il driver non ha un nome", () => {
    const result = parseSarif(sarif({ runs: [{ tool: { driver: {} }, results: [] }] }));
    expect((result as { toolName: string | null }).toolName).toBeNull();
  });

  it("mappa il livello SARIF sulla gravità quando non c'è security-severity", () => {
    const doc = sarif({
      runs: [
        {
          tool: { driver: { name: "Semgrep OSS", rules: [] } },
          results: [
            { ruleId: "r1", level: "error", message: { text: "errore grave" } },
            { ruleId: "r2", level: "warning", message: { text: "attenzione" } },
            { ruleId: "r3", level: "note", message: { text: "nota" } },
            { ruleId: "r4", message: { text: "senza livello" } },
          ],
        },
      ],
    });
    const result = parseSarif(doc) as { bySeverity: Record<string, number>; totalFindings: number };
    expect(result.totalFindings).toBe(4);
    expect(result.bySeverity).toEqual({ critical: 0, high: 1, medium: 1, low: 2 });
  });

  it("usa security-severity della regola quando presente, ignorando il livello", () => {
    const doc = sarif({
      runs: [
        {
          tool: { driver: { name: "CodeQL", rules: [{ id: "r1", properties: { "security-severity": "9.5" } }] } },
          results: [{ ruleId: "r1", level: "note", message: { text: "sql injection" } }],
        },
      ],
    });
    const result = parseSarif(doc) as { bySeverity: Record<string, number> };
    expect(result.bySeverity.critical).toBe(1);
    expect(result.bySeverity.low).toBe(0);
  });

  it("recupera file e riga dalla posizione fisica del risultato", () => {
    const doc = sarif({
      runs: [
        {
          tool: { driver: { name: "Snyk Code", rules: [] } },
          results: [
            {
              ruleId: "r1",
              level: "error",
              message: { text: "problema" },
              locations: [{ physicalLocation: { artifactLocation: { uri: "src/app.ts" }, region: { startLine: 42 } } }],
            },
          ],
        },
      ],
    });
    const result = parseSarif(doc) as { findings: Array<{ file: string | null; line: number | null }> };
    expect(result.findings[0].file).toBe("src/app.ts");
    expect(result.findings[0].line).toBe(42);
  });

  it("usa la shortDescription della regola come messaggio di riserva", () => {
    const doc = sarif({
      runs: [
        {
          tool: { driver: { name: "Snyk Code", rules: [{ id: "r1", shortDescription: { text: "Descrizione della regola" } }] } },
          results: [{ ruleId: "r1", level: "error" }],
        },
      ],
    });
    const result = parseSarif(doc) as { findings: Array<{ message: string }> };
    expect(result.findings[0].message).toBe("Descrizione della regola");
  });

  it("ordina i risultati restituiti per gravità, dal più grave al meno grave", () => {
    const doc = sarif({
      runs: [
        {
          tool: { driver: { name: "Snyk Code", rules: [] } },
          results: [
            { ruleId: "a", level: "note", message: { text: "basso" } },
            { ruleId: "b", level: "error", message: { text: "alto" } },
            { ruleId: "c", level: "warning", message: { text: "medio" } },
          ],
        },
      ],
    });
    const result = parseSarif(doc) as { findings: Array<{ severity: string }> };
    expect(result.findings.map((f) => f.severity)).toEqual(["high", "medium", "low"]);
  });

  it("conta tutti i risultati in totalFindings ma limita i findings restituiti a 300", () => {
    const results = Array.from({ length: 350 }, (_, i) => ({
      ruleId: `r${i}`,
      level: "warning",
      message: { text: `problema ${i}` },
    }));
    const doc = sarif({ runs: [{ tool: { driver: { name: "Snyk Code", rules: [] } }, results }] });
    const result = parseSarif(doc) as { totalFindings: number; returnedFindings: number; findings: unknown[] };
    expect(result.totalFindings).toBe(350);
    expect(result.returnedFindings).toBe(300);
    expect(result.findings).toHaveLength(300);
    expect(result.bySeverity.medium).toBe(350);
  });

  it("somma i risultati su più run mantenendo il primo nome di strumento trovato", () => {
    const doc = sarif({
      runs: [
        { tool: { driver: { name: "Snyk Code", rules: [] } }, results: [{ ruleId: "a", level: "error" }] },
        { tool: { driver: { rules: [] } }, results: [{ ruleId: "b", level: "warning" }] },
      ],
    });
    const result = parseSarif(doc) as { toolName: string | null; totalFindings: number };
    expect(result.toolName).toBe("Snyk Code");
    expect(result.totalFindings).toBe(2);
  });
});
