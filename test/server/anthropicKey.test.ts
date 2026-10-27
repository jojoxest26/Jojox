import { afterEach, describe, expect, it, vi } from "vitest";

async function loadAnthropic() {
  vi.resetModules();
  return import("../../src/server/anthropic.js");
}

describe("assertAnthropicKeySafe", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("does nothing when the key is missing (handled separately as 503 elsewhere)", async () => {
    vi.stubEnv("ANTHROPIC_API_KEY", "");
    const { assertAnthropicKeySafe } = await loadAnthropic();
    expect(() => assertAnthropicKeySafe()).not.toThrow();
  });

  it("does nothing for a normal ASCII key", async () => {
    vi.stubEnv("ANTHROPIC_API_KEY", "sk-ant-abc123");
    const { assertAnthropicKeySafe } = await loadAnthropic();
    expect(() => assertAnthropicKeySafe()).not.toThrow();
  });

  it("throws a clear, specific error when the key contains a non-ASCII masking character", async () => {
    vi.stubEnv("ANTHROPIC_API_KEY", "sk-ant-•bc123");
    const { assertAnthropicKeySafe } = await loadAnthropic();
    expect(() => assertAnthropicKeySafe()).toThrow(/carattere non valido/);
  });
});
