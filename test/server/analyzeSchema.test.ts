import { describe, expect, it } from "vitest";
import { requestSchema } from "../../src/server/routes/analyze.js";

describe("analyze request schema", () => {
  it("accepts a valid file list", () => {
    const result = requestSchema.safeParse({ files: [{ path: "src/index.ts", content: "export {}" }] });
    expect(result.success).toBe(true);
  });

  it("rejects an empty file list", () => {
    const result = requestSchema.safeParse({ files: [] });
    expect(result.success).toBe(false);
  });

  it("rejects a missing files field", () => {
    const result = requestSchema.safeParse({});
    expect(result.success).toBe(false);
  });

  it("rejects a file with an empty path", () => {
    const result = requestSchema.safeParse({ files: [{ path: "", content: "x" }] });
    expect(result.success).toBe(false);
  });

  it("rejects more than 300 files", () => {
    const files = Array.from({ length: 301 }, (_, i) => ({ path: `src/file${i}.ts`, content: "x" }));
    const result = requestSchema.safeParse({ files });
    expect(result.success).toBe(false);
  });

  it("rejects a single file larger than 200KB", () => {
    const result = requestSchema.safeParse({
      files: [{ path: "src/big.ts", content: "x".repeat(200_001) }],
    });
    expect(result.success).toBe(false);
  });
});
