import { describe, expect, it } from "vitest";
import { parseAiInsightsResponse, selectFilesForReview } from "../../src/server/aiInsights.js";

describe("parseAiInsightsResponse", () => {
  it("analizza un array JSON valido", () => {
    const text = JSON.stringify([
      { category: "race-condition", title: "Stato condiviso senza lock", file: "src/cache.ts", explanation: "..." },
    ]);
    expect(parseAiInsightsResponse(text)).toEqual([
      { category: "race-condition", title: "Stato condiviso senza lock", file: "src/cache.ts", explanation: "..." },
    ]);
  });

  it("ignora testo prima e dopo l'array", () => {
    const text = `Ecco i risultati:\n[{"category":"authorization-logic","title":"x","file":"y","explanation":"z"}]\nFine.`;
    expect(parseAiInsightsResponse(text)).toHaveLength(1);
  });

  it("ritorna array vuoto quando il modello non trova nulla", () => {
    expect(parseAiInsightsResponse("[]")).toEqual([]);
  });

  it("ritorna array vuoto su JSON malformato invece di lanciare un'eccezione", () => {
    expect(parseAiInsightsResponse("non è json")).toEqual([]);
    expect(parseAiInsightsResponse("[{\"category\": broken")).toEqual([]);
  });

  it("scarta elementi con una categoria non valida o campi mancanti", () => {
    const text = JSON.stringify([
      { category: "sql-injection", title: "x", file: "y", explanation: "z" },
      { category: "race-condition", title: "", file: "y", explanation: "z" },
      { category: "race-condition", file: "y", explanation: "z" },
      { category: "authorization-logic", title: "valido", file: "y", explanation: "z" },
    ]);
    const result = parseAiInsightsResponse(text);
    expect(result).toHaveLength(1);
    expect(result[0].title).toBe("valido");
  });

  it("taglia a un massimo di 8 risultati", () => {
    const many = Array.from({ length: 20 }, (_, i) => ({
      category: "race-condition",
      title: `bug ${i}`,
      file: "a.ts",
      explanation: "...",
    }));
    expect(parseAiInsightsResponse(JSON.stringify(many))).toHaveLength(8);
  });
});

describe("selectFilesForReview", () => {
  it("passa invariati pochi file piccoli", () => {
    const files = [
      { path: "a.ts", content: "const a = 1;" },
      { path: "b.ts", content: "const b = 2;" },
    ];
    expect(selectFilesForReview(files)).toEqual(files);
  });

  it("tronca un singolo file troppo grande invece di scartarlo", () => {
    const huge = "x".repeat(10_000);
    const [selected] = selectFilesForReview([{ path: "big.ts", content: huge }]);
    expect(selected.content.length).toBeLessThan(huge.length);
  });

  it("si ferma a 40 file anche se ne arrivano di più", () => {
    const files = Array.from({ length: 100 }, (_, i) => ({ path: `f${i}.ts`, content: "x" }));
    expect(selectFilesForReview(files)).toHaveLength(40);
  });

  it("smette di aggiungere file una volta superato il tetto totale di caratteri", () => {
    const files = Array.from({ length: 30 }, (_, i) => ({ path: `f${i}.ts`, content: "x".repeat(5_000) }));
    const selected = selectFilesForReview(files);
    const totalChars = selected.reduce((sum, f) => sum + f.content.length, 0);
    expect(totalChars).toBeLessThanOrEqual(120_000);
  });

  it("segnala in modo esplicito un file troncato, invece di lasciarlo sembrare completo", () => {
    const huge = "x".repeat(10_000);
    const [selected] = selectFilesForReview([{ path: "big.ts", content: huge }]);
    expect(selected.content).toContain("troncato");
  });

  it("manda prima i file di route/auth quando il progetto supera il limite di 40 file", () => {
    const noise = Array.from({ length: 45 }, (_, i) => ({ path: `src/utils/helper${i}.ts`, content: "x" }));
    const relevant = { path: "src/server/routes/team.ts", content: "x" };
    const selected = selectFilesForReview([...noise, relevant]);
    expect(selected.map((f) => f.path)).toContain("src/server/routes/team.ts");
  });

  it("non cambia l'ordine tra file della stessa priorità", () => {
    const files = [
      { path: "src/server/routes/a.ts", content: "a" },
      { path: "src/server/routes/b.ts", content: "b" },
      { path: "src/utils/c.ts", content: "c" },
      { path: "src/utils/d.ts", content: "d" },
    ];
    expect(selectFilesForReview(files).map((f) => f.path)).toEqual([
      "src/server/routes/a.ts",
      "src/server/routes/b.ts",
      "src/utils/c.ts",
      "src/utils/d.ts",
    ]);
  });
});
