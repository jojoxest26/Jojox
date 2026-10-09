import { describe, expect, it, vi } from "vitest";
import { fetchRepoFiles } from "../../src/server/github/repoContent.js";

describe("fetchRepoFiles", () => {
  it("scarica solo i blob di testo rilevanti, saltando cartelle, binari e file troppo grandi", async () => {
    const tree = [
      { path: "src/index.ts", type: "blob", sha: "sha-index", size: 100 },
      { path: "src", type: "tree", sha: "sha-dir" }, // una cartella, non un file
      { path: "logo.png", type: "blob", sha: "sha-logo", size: 50 }, // binario
      { path: "node_modules/pkg/index.js", type: "blob", sha: "sha-nm", size: 10 }, // SKIP_PATH
      { path: "huge.js", type: "blob", sha: "sha-huge", size: 300_000 }, // troppo grande
    ];

    const request = vi
      .fn()
      .mockResolvedValueOnce({ data: { default_branch: "main" } }) // GET repo
      .mockResolvedValueOnce({ data: { object: { sha: "base-sha" } } }) // GET ref
      .mockResolvedValueOnce({ data: { tree } }) // GET tree recursive
      .mockResolvedValueOnce({ data: { encoding: "base64", content: Buffer.from("console.log(1)").toString("base64") } }); // GET blob (solo src/index.ts)

    const snapshot = await fetchRepoFiles({ request } as any, { owner: "acme", repo: "app" });

    expect(snapshot.branch).toBe("main");
    expect(snapshot.files).toEqual([{ path: "src/index.ts", content: "console.log(1)" }]);

    const blobCall = request.mock.calls[3];
    expect(blobCall[0]).toBe("GET /repos/{owner}/{repo}/git/blobs/{file_sha}");
    expect(blobCall[1].file_sha).toBe("sha-index");
  });

  it("torna una lista vuota se la lettura di un blob fallisce, senza bloccare gli altri", async () => {
    const tree = [
      { path: "a.ts", type: "blob", sha: "sha-a", size: 10 },
      { path: "b.ts", type: "blob", sha: "sha-b", size: 10 },
    ];

    const request = vi.fn().mockImplementation(async (route: string, params: any) => {
      if (route === "GET /repos/{owner}/{repo}") return { data: { default_branch: "main" } };
      if (route === "GET /repos/{owner}/{repo}/git/ref/{ref}") return { data: { object: { sha: "base-sha" } } };
      if (route === "GET /repos/{owner}/{repo}/git/trees/{tree_sha}") return { data: { tree } };
      if (route === "GET /repos/{owner}/{repo}/git/blobs/{file_sha}") {
        if (params.file_sha === "sha-a") throw new Error("boom");
        return { data: { encoding: "base64", content: Buffer.from("ok").toString("base64") } };
      }
      throw new Error(`rotta non attesa: ${route}`);
    });

    const snapshot = await fetchRepoFiles({ request } as any, { owner: "acme", repo: "app" });

    expect(snapshot.files).toEqual([{ path: "b.ts", content: "ok" }]);
  });
});
