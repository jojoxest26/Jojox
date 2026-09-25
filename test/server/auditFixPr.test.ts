import { describe, expect, it, vi } from "vitest";
import { openAuditFixPr, listInstallationRepos } from "../../src/server/github/auditFixPr.js";

describe("openAuditFixPr", () => {
  it("crea un branch dal branch predefinito del repo e apre una PR verso di esso", async () => {
    const request = vi
      .fn()
      .mockResolvedValueOnce({ data: { default_branch: "main" } }) // GET repo
      .mockResolvedValueOnce({ data: { object: { sha: "base-sha" } } }) // GET ref
      .mockResolvedValueOnce({ data: { sha: "tree-sha" } }) // POST trees
      .mockResolvedValueOnce({ data: { sha: "commit-sha" } }) // POST commits
      .mockResolvedValueOnce({ data: {} }) // POST refs (create branch)
      .mockResolvedValueOnce({ data: { html_url: "https://github.com/acme/app/pull/42" } }); // POST pulls

    const url = await openAuditFixPr(
      { request } as any,
      {
        owner: "acme",
        repo: "app",
        changedFiles: [{ path: "src/index.ts", content: "fixed" }],
        fixedCheckIds: new Set(["hardcoded-secret"]),
        filesChanged: 1,
      }
    );

    expect(url).toBe("https://github.com/acme/app/pull/42");
    expect(request).toHaveBeenCalledTimes(6);

    const refCall = request.mock.calls[1];
    expect(refCall[1].ref).toBe("heads/main");

    const treeCall = request.mock.calls[2];
    expect(treeCall[1].base_tree).toBe("base-sha");
    expect(treeCall[1].tree).toEqual([{ path: "src/index.ts", mode: "100644", type: "blob", content: "fixed" }]);

    const commitCall = request.mock.calls[3];
    expect(commitCall[1].parents).toEqual(["base-sha"]);

    const pullCall = request.mock.calls[5];
    expect(pullCall[1].base).toBe("main");
  });
});

describe("listInstallationRepos", () => {
  it("segue la paginazione finché una pagina torna meno di 100 repository", async () => {
    const page1 = Array.from({ length: 100 }, (_, i) => ({
      owner: { login: "acme" },
      name: `repo${i}`,
      full_name: `acme/repo${i}`,
    }));
    const page2 = [{ owner: { login: "acme" }, name: "last", full_name: "acme/last" }];
    const request = vi
      .fn()
      .mockResolvedValueOnce({ data: { repositories: page1 } })
      .mockResolvedValueOnce({ data: { repositories: page2 } });

    const repos = await listInstallationRepos({ request } as any);

    expect(request).toHaveBeenCalledTimes(2);
    expect(repos).toHaveLength(101);
    expect(repos[100]).toEqual({ owner: "acme", repo: "last", fullName: "acme/last" });
  });

  it("si ferma alla prima pagina se ci sono meno di 100 repository", async () => {
    const page1 = [{ owner: { login: "acme" }, name: "app", full_name: "acme/app" }];
    const request = vi.fn().mockResolvedValueOnce({ data: { repositories: page1 } });

    const repos = await listInstallationRepos({ request } as any);

    expect(request).toHaveBeenCalledTimes(1);
    expect(repos).toEqual([{ owner: "acme", repo: "app", fullName: "acme/app" }]);
  });
});