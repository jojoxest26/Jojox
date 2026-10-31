import { describe, expect, it } from "vitest";
import { excludeSelfScanFixtures, isSelfRepo } from "../../src/server/util/selfScanFixtures.js";

describe("isSelfRepo", () => {
  it("recognizes our own repository", () => {
    expect(isSelfRepo("jojoxest26", "jojox")).toBe(true);
  });

  it("is case-insensitive", () => {
    expect(isSelfRepo("JoJoXest26", "JoJoX")).toBe(true);
  });

  it("rejects any other owner or repo", () => {
    expect(isSelfRepo("acme", "jojox")).toBe(false);
    expect(isSelfRepo("jojoxest26", "other-repo")).toBe(false);
    expect(isSelfRepo("someone-else", "unrelated")).toBe(false);
  });
});

describe("excludeSelfScanFixtures", () => {
  const files = [
    { path: "src/checks/high.ts", content: "contains md5(password) as a documented example" },
    { path: "src/checks/medium.ts", content: "contains redirect(\"/\") in an explanatory comment" },
    { path: "test/checks.high.test.ts", content: "fixture: hashlib.md5(password).hexdigest()" },
    { path: "test/cloudConfigChecks.test.ts", content: "fixture for cloud config checks" },
    { path: "web/src/i18n/checkTranslations.ts", content: "translated fix examples: SUPABASE_SERVICE_ROLE_KEY" },
    { path: "src/index.ts", content: "real application code, unrelated to the check engine" },
    { path: "web/src/App.tsx", content: "real frontend code" },
  ];

  it("leaves everything untouched for any repository that isn't our own", () => {
    const result = excludeSelfScanFixtures(files, "someone-else", "their-app");
    expect(result).toEqual(files);
  });

  it("drops src/checks/, test/ and the translated check descriptions for jojoxest26/jojox, keeps real source", () => {
    const result = excludeSelfScanFixtures(files, "jojoxest26", "jojox");
    expect(result.map((f) => f.path)).toEqual(["src/index.ts", "web/src/App.tsx"]);
  });

  it("does not drop a real customer file that happens to share the translations file's name", () => {
    const otherRepoFiles = [{ path: "web/src/i18n/checkTranslations.ts", content: "real customer code" }];
    const result = excludeSelfScanFixtures(otherRepoFiles, "someone-else", "their-app");
    expect(result).toEqual(otherRepoFiles);
  });

  it("is a no-op on an empty file list", () => {
    expect(excludeSelfScanFixtures([], "jojoxest26", "jojox")).toEqual([]);
  });
});
