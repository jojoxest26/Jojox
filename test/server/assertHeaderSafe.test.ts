import { describe, expect, it } from "vitest";
import { assertHeaderSafe } from "../../src/server/util/assertHeaderSafe.js";

describe("assertHeaderSafe", () => {
  it("does nothing for a normal ASCII string", () => {
    expect(() => assertHeaderSafe("sk_test_abc123", "SOME_KEY")).not.toThrow();
  });

  it("throws a clear, specific error on a non-ASCII masking character", () => {
    // "•" (bullet, U+2022) — ciò che resta da un copia-incolla incompleto su Railway.
    expect(() => assertHeaderSafe("sk_test_•bc123", "SOME_KEY")).toThrow(/carattere non valido/);
  });

  it("names the field in the error message", () => {
    expect(() => assertHeaderSafe("•", "ANTHROPIC_API_KEY")).toThrow(/ANTHROPIC_API_KEY/);
  });
});
