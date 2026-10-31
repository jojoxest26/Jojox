import { describe, expect, it } from "vitest";
import { buildSystemPrompt, SUPPORTED_CHAT_LANGS, LANGUAGE_NAMES, type ChatLang } from "../../src/server/routes/chat.js";
import { ALL_CHECKS } from "../../src/checks/index.js";

const SAMPLE_FINDING = {
  checkId: "hardcoded-secret",
  severity: "critical" as const,
  confidence: "confirmed" as const,
  title: "Secret hardcoded",
  description: "A secret is written directly in the code.",
  file: "src/index.ts",
  line: 10,
  snippet: "const key = \"sk_live_...\"",
  fix: { before: "const key = \"sk_live_...\"", after: "const key = process.env.KEY" },
};

describe("buildSystemPrompt across all 23 chat languages", () => {
  it.each(SUPPORTED_CHAT_LANGS)("builds a non-empty, well-formed prompt in general mode for '%s'", (lang: ChatLang) => {
    const prompt = buildSystemPrompt([], null, lang);
    expect(prompt.length).toBeGreaterThan(50);
    expect(prompt).toContain("JoJoX");
    // Le cifre dei fatti di prodotto non vanno mai perse in traduzione.
    // (Niente separatore delle migliaia qui: IT usa "1.490", EN "1,490".)
    expect(prompt).toContain(String(ALL_CHECKS.length));
    expect(prompt).toContain("190");
    expect(prompt).toContain("490");
    expect(prompt).toContain("500");
  });

  it.each(SUPPORTED_CHAT_LANGS)("builds a non-empty, well-formed prompt in findings mode for '%s'", (lang: ChatLang) => {
    const prompt = buildSystemPrompt([SAMPLE_FINDING], 72, lang);
    expect(prompt.length).toBeGreaterThan(50);
    expect(prompt).toContain("JoJoX");
    expect(prompt).toContain("72");
    expect(prompt).toContain("Secret hardcoded");
  });

  it("writes the IT prompt in Italian with no explicit language-override instruction", () => {
    const prompt = buildSystemPrompt([], null, "it");
    expect(prompt).toContain("Sei l'assistente di JoJoX");
    expect(prompt).not.toContain("Reply in");
  });

  it("writes the EN prompt in English with no explicit language-override instruction", () => {
    const prompt = buildSystemPrompt([], null, "en");
    expect(prompt).toContain("You are the JoJoX assistant");
    expect(prompt).not.toContain("Reply in");
  });

  const otherLangs = SUPPORTED_CHAT_LANGS.filter((l) => l !== "it" && l !== "en");

  it.each(otherLangs)("appends an explicit 'Reply in <language>' instruction for '%s'", (lang: ChatLang) => {
    const prompt = buildSystemPrompt([], null, lang);
    expect(prompt).toContain(`Reply in ${LANGUAGE_NAMES[lang]}`);
    // Il corpo del prompt resta quello inglese: i fatti di prodotto non sono
    // duplicati in altre 21 lingue, solo l'istruzione finale cambia lingua bersaglio.
    expect(prompt).toContain("You are the JoJoX assistant");
  });

  it("gives every supported language a distinct English name", () => {
    const names = SUPPORTED_CHAT_LANGS.map((l) => LANGUAGE_NAMES[l]);
    expect(new Set(names).size).toBe(names.length);
  });
});
