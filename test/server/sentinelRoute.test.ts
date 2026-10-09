import { describe, expect, it } from "vitest";
import { secretsMatch } from "../../src/server/routes/sentinel.js";

describe("secretsMatch", () => {
  it("accetta due stringhe identiche", () => {
    expect(secretsMatch("abc123", "abc123")).toBe(true);
  });

  it("rifiuta due stringhe diverse della stessa lunghezza", () => {
    expect(secretsMatch("abc123", "abc124")).toBe(false);
  });

  it("rifiuta stringhe di lunghezza diversa senza lanciare un errore", () => {
    expect(secretsMatch("abc", "abcdef")).toBe(false);
  });

  it("rifiuta una stringa vuota contro un segreto non vuoto", () => {
    expect(secretsMatch("", "abc")).toBe(false);
  });
});
