import { BINARY_EXT } from "../../analyze.js";
import { SKIP_PATH } from "../../util/skipPath.js";
import type { SourceFile } from "../../types.js";
import { mapWithConcurrency } from "../util/concurrency.js";
import { getGithubApp } from "./app.js";
import { getDefaultBranchHead } from "./auditFixPr.js";

type InstallationOctokit = Awaited<ReturnType<Awaited<ReturnType<typeof getGithubApp>>["getInstallationOctokit"]>>;

// Un repository intero può avere molti più file di quanti ne servano per
// un'analisi utile: stessi limiti già usati per il Full Site Audit, l'altro
// punto in cui scarichiamo un intero progetto invece di poche modifiche.
const MAX_FILES = 2000;
const MAX_FILE_BYTES = 200_000;
// Quanti blob scarichiamo in parallelo — stesso criterio di listChangedFiles
// per le pull request: abbastanza per essere veloci, abbastanza poco per non
// rischiare i rate limit "secondari" di GitHub su repository con molti file.
const BLOB_FETCH_CONCURRENCY = 8;

export interface RepoSnapshot {
  branch: string;
  files: SourceFile[];
}

/**
 * Scarica il contenuto di (fino a) MAX_FILES file di testo dal branch
 * predefinito di un repository, usando l'albero Git invece dell'API
 * "contents" per singolo file: una sola chiamata per elencare tutto il
 * repository, poi una per ogni blob da leggere — serve alla Sentinella 24/7
 * per rileggere l'intero repository ogni notte, non solo i file cambiati in
 * una pull request.
 */
export async function fetchRepoFiles(
  octokit: Pick<InstallationOctokit, "request">,
  params: { owner: string; repo: string }
): Promise<RepoSnapshot> {
  const { owner, repo } = params;
  const { branch, sha } = await getDefaultBranchHead(octokit as InstallationOctokit, { owner, repo });

  const { data: tree } = await octokit.request("GET /repos/{owner}/{repo}/git/trees/{tree_sha}", {
    owner,
    repo,
    tree_sha: sha,
    recursive: "true",
  });

  const candidates = tree.tree.filter(
    (entry): entry is typeof entry & { path: string; sha: string; size: number } =>
      entry.type === "blob" &&
      !!entry.path &&
      !!entry.sha &&
      typeof entry.size === "number" &&
      entry.size <= MAX_FILE_BYTES &&
      !SKIP_PATH.test(entry.path) &&
      !BINARY_EXT.test(entry.path)
  );

  const fetched = await mapWithConcurrency(candidates.slice(0, MAX_FILES), BLOB_FETCH_CONCURRENCY, async (entry): Promise<SourceFile | null> => {
    try {
      const { data } = await octokit.request("GET /repos/{owner}/{repo}/git/blobs/{file_sha}", {
        owner,
        repo,
        file_sha: entry.sha,
      });
      if (data.encoding !== "base64") return null;
      return { path: entry.path, content: Buffer.from(data.content, "base64").toString("utf8") };
    } catch (err) {
      console.error(`impossibile leggere ${entry.path} da ${owner}/${repo}`, err);
      return null;
    }
  });

  return { branch, files: fetched.filter((f): f is SourceFile => f !== null) };
}
