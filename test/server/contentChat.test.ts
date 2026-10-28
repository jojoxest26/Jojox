import { describe, expect, it } from "vitest";
import { buildContentSystemPrompt, extractReel, isContentAdmin } from "../../src/server/routes/contentChat.js";
import { parseEmailList } from "../../src/server/env.js";

const VALID_REEL = {
  title: "Prova",
  voiceover: "Mentre gli altri buttano tempo...",
  caption: "Prova #jojox",
  scenes: [
    { type: "word", text: "tutte", bg: "dark", duration: 0.6 },
    { type: "headline", line1: "MENTRE GLI ALTRI", line2: "BUTTANO TEMPO", chips: ["🐞 Bug"], bg: "dark", accent: "red", duration: 2 },
    { type: "strike", words: ["A mano", "61 controlli"], bg: "light", duration: 2 },
    { type: "stat", value: 61, caption: "controlli", bg: "dark", accent: "blue", duration: 2 },
    { type: "cta", text: "Provalo gratis", sub: "jojox.it", bg: "dark", accent: "red", duration: 2 },
  ],
};

describe("content chat access", () => {
  it("parses the admin email list case-insensitively", () => {
    expect(parseEmailList(" A@x.it, b@y.com ,,")).toEqual(["a@x.it", "b@y.com"]);
    expect(parseEmailList(undefined)).toEqual([]);
  });

  it("only lets listed emails in, and nobody when the list is empty", () => {
    expect(isContentAdmin("A@X.it", ["a@x.it"])).toBe(true);
    expect(isContentAdmin("other@x.it", ["a@x.it"])).toBe(false);
    expect(isContentAdmin(undefined, ["a@x.it"])).toBe(false);
    expect(isContentAdmin("a@x.it", [])).toBe(false);
  });
});

describe("extractReel", () => {
  it("splits the chat text from a valid reel block", () => {
    const raw = `Ecco l'idea.\n\n\`\`\`reel\n${JSON.stringify(VALID_REEL)}\n\`\`\``;
    const { text, reel, reelError } = extractReel(raw);
    expect(text).toBe("Ecco l'idea.");
    expect(reelError).toBe(false);
    expect(reel?.scenes).toHaveLength(5);
  });

  it("clamps scene durations instead of rejecting the reel", () => {
    const reelJson = { ...VALID_REEL, scenes: [{ type: "word", text: "x", bg: "dark", duration: 30 }] };
    const { reel } = extractReel("```reel\n" + JSON.stringify(reelJson) + "\n```");
    expect(reel?.scenes[0].duration).toBe(5);
  });

  it("flags a malformed reel without failing", () => {
    const { text, reel, reelError } = extractReel("Ciao\n```reel\n{ not json\n```");
    expect(text).toBe("Ciao");
    expect(reel).toBeNull();
    expect(reelError).toBe(true);
  });

  it("returns plain text when there is no reel block", () => {
    expect(extractReel("Solo idee")).toEqual({ text: "Solo idee", reel: null, reelError: false });
  });
});

describe("buildContentSystemPrompt", () => {
  it("is grounded on the site facts and forbids invented data", () => {
    const prompt = buildContentSystemPrompt(null);
    expect(prompt).toContain("61");
    expect(prompt).toContain("jojox.it");
    expect(prompt).toContain("Mai inventare");
  });

  it("includes the reel currently open in the preview", () => {
    const prompt = buildContentSystemPrompt(VALID_REEL as never);
    expect(prompt).toContain("BUTTANO TEMPO");
  });
});
