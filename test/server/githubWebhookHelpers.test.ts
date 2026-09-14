import { describe, expect, it, vi } from "vitest";
import { listChangedFiles, mapWithConcurrency } from "../../src/server/routes/webhooks/github.js";

describe("mapWithConcurrency", () => {
  it("preserva l'ordine dei risultati anche se finiscono in tempi diversi", async () => {
    const delays = [30, 10, 20];
    const result = await mapWithConcurrency(delays, 2, (ms) => new Promise<number>((resolve) => setTimeout(() => resolve(ms), ms)));
    expect(result).toEqual(delays);
  });

  it("non supera mai il numero massimo di chiamate in parallelo", async () => {
    let inFlight = 0;
    let maxInFlight = 0;
    const items = Array.from({ length: 20 }, (_, i) => i);

    await mapWithConcurrency(items, 3, async (i) => {
      inFlight++;
      maxInFlight = Math.max(maxInFlight, inFlight);
      await new Promise((resolve) => setTimeout(resolve, 1));
      inFlight--;
      return i;
    });

    expect(maxInFlight).toBeLessThanOrEqual(3);
  });

  it("funziona anche con una lista vuota", async () => {
    const result = await mapWithConcurrency([], 5, async (x) => x);
    expect(result).toEqual([]);
  });
});

describe("listChangedFiles", () => {
  it("segue la paginazione finché una pagina torna meno di 100 file", async () => {
    const page1 = Array.from({ length: 100 }, (_, i) => ({ filename: `a${i}.ts`, status: "modified", patch: "@@" }));
    const page2 = [{ filename: "b.ts", status: "modified", patch: "@@" }];
    const request = vi
      .fn()
      .mockResolvedValueOnce({ data: page1 })
      .mockResolvedValueOnce({ data: page2 });

    const files = await listChangedFiles({ request }, { owner: "acme", repo: "app", pull_number: 1 });

    expect(request).toHaveBeenCalledTimes(2);
    expect(files).toHaveLength(101);
    expect(files[100].filename).toBe("b.ts");
  });

  it("si ferma alla prima pagina se ci sono meno di 100 file", async () => {
    const page1 = [{ filename: "a.ts", status: "modified", patch: "@@" }];
    const request = vi.fn().mockResolvedValueOnce({ data: page1 });

    const files = await listChangedFiles({ request }, { owner: "acme", repo: "app", pull_number: 1 });

    expect(request).toHaveBeenCalledTimes(1);
    expect(files).toEqual(page1);
  });
});