import { getGithubApp } from "./app.js";
import { ALL_CHECKS } from "../../checks/index.js";
import type { SourceFile } from "../../types.js";

type InstallationOctokit = Awaited<ReturnType<Awaited<ReturnType<typeof getGithubApp>>["getInstallationOctokit"]>>;

function buildAuditFixPrBody(fixedCheckIds: Set<string>, filesChanged: number): string {
  const titles = ALL_CHECKS.filter((c) => fixedCheckIds.has(c.id)).map((c) => `- ${c.title}`);
  return [
    `JoJoX ha corretto in automatico **${filesChanged}** ${filesChanged === 1 ? "file" : "file"} per **${fixedCheckIds.size}** ${fixedCheckIds.size === 1 ? "tipo di problema" : "tipi di problema"}, individuati durante un Full Site Audit:`,
    "",
    ...titles,
    "",
    "Nessun LLM: stesse regole usate dall'analisi, applicate in automatico. Controlla il diff prima di unire — questa correzione non è mai stata applicata direttamente al branch principale.",
  ].join("\n");
}

/** Branch predefinito di un repository e lo sha del suo ultimo commit. */
async function getDefaultBranchHead(
  octokit: InstallationOctokit,
  params: { owner: string; repo: string }
): Promise<{ branch: string; sha: string }> {
  const { owner, repo } = params;
  const { data: repoInfo } = await octokit.request("GET /repos/{owner}/{repo}", { owner, repo });
  const branch = repoInfo.default_branch;

  const { data: baseRef } = await octokit.request("GET /repos/{owner}/{repo}/git/ref/{ref}", {
    owner,
    repo,
    ref: `heads/${branch}`,
  });
  return { branch, sha: baseRef.object.sha };
}

/**
 * Tutti i percorsi dei file già presenti nel branch predefinito del
 * repository — usato per controllare che i file caricati per un Full Site
 * Audit corrispondano davvero a quel repository, prima di aprirci una Pull
 * Request. Senza questo controllo, scegliere per sbaglio il repository
 * sbagliato nel menu aprirebbe comunque una PR con contenuti a caso.
 */
export async function getRepoFilePaths(octokit: InstallationOctokit, params: { owner: string; repo: string }): Promise<Set<string>> {
  const { owner, repo } = params;
  const { sha } = await getDefaultBranchHead(octokit, { owner, repo });
  const { data: tree } = await octokit.request("GET /repos/{owner}/{repo}/git/trees/{tree_sha}", {
    owner,
    repo,
    tree_sha: sha,
    recursive: "true",
  });
  return new Set(tree.tree.filter((entry) => entry.type === "blob" && entry.path).map((entry) => entry.path!));
}

/**
 * Apre una Pull Request con le correzioni automatiche del Full Site Audit
 * verso il branch principale del repository — a differenza del fix del
 * monitoraggio continuo (legato a una pull request esistente), qui non ce
 * n'è una: il branch di partenza è sempre l'ultimo stato del branch
 * predefinito del repository.
 */
export async function openAuditFixPr(
  octokit: InstallationOctokit,
  params: {
    owner: string;
    repo: string;
    changedFiles: SourceFile[];
    fixedCheckIds: Set<string>;
    filesChanged: number;
  }
): Promise<string> {
  const { owner, repo, changedFiles, fixedCheckIds, filesChanged } = params;

  const { branch: baseBranch, sha: baseSha } = await getDefaultBranchHead(octokit, { owner, repo });

  const { data: tree } = await octokit.request("POST /repos/{owner}/{repo}/git/trees", {
    owner,
    repo,
    base_tree: baseSha,
    tree: changedFiles.map((f) => ({ path: f.path, mode: "100644" as const, type: "blob" as const, content: f.content })),
  });

  const { data: commit } = await octokit.request("POST /repos/{owner}/{repo}/git/commits", {
    owner,
    repo,
    message: "JoJoX: correzioni automatiche dal Full Site Audit",
    tree: tree.sha,
    parents: [baseSha],
  });

  const branchName = `jojox-audit-fixes/${Date.now()}`;
  await octokit.request("POST /repos/{owner}/{repo}/git/refs", {
    owner,
    repo,
    ref: `refs/heads/${branchName}`,
    sha: commit.sha,
  });

  const { data: pr } = await octokit.request("POST /repos/{owner}/{repo}/pulls", {
    owner,
    repo,
    title: "JoJoX: correzioni automatiche (Full Site Audit)",
    head: branchName,
    base: baseBranch,
    body: buildAuditFixPrBody(fixedCheckIds, filesChanged),
  });

  return pr.html_url;
}

/** Elenca i repository accessibili a un'installazione della GitHub App. */
export async function listInstallationRepos(octokit: InstallationOctokit): Promise<{ owner: string; repo: string; fullName: string }[]> {
  const repos: { owner: string; repo: string; fullName: string }[] = [];
  for (let page = 1; ; page++) {
    const { data } = await octokit.request("GET /installation/repositories", { per_page: 100, page });
    for (const r of data.repositories) {
      repos.push({ owner: r.owner.login, repo: r.name, fullName: r.full_name });
    }
    if (data.repositories.length < 100) break;
  }
  return repos;
}