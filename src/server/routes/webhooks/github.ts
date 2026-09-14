import { Router, raw } from "express";
import { env } from "../../env.js";
import { verifyGithubSignature } from "../../github/verifySignature.js";
import { getGithubApp } from "../../github/app.js";
import { analyzeFiles, applyAutofixes } from "../../../analyze.js";
import { ALL_CHECKS } from "../../../checks/index.js";
import { checkRunConclusion, formatPrComment } from "../../github/report.js";
import { supabaseAdmin } from "../../db/supabase.js";
import { notifySlack } from "../../slack/notify.js";
import type { SourceFile } from "../../../types.js";

interface InstallationPayload {
  action: string;
  installation: {
    id: number;
    account: { login: string; type: string };
  };
}

interface PullRequestPayload {
  action: string;
  installation: { id: number };
  repository: { name: string; owner: { login: string } };
  pull_request: { number: number; head: { sha: string; ref: string } };
}

type InstallationOctokit = Awaited<ReturnType<Awaited<ReturnType<typeof getGithubApp>>["getInstallationOctokit"]>>;

export const githubWebhookRouter = Router();

const HANDLED_PR_ACTIONS = new Set(["opened", "synchronize", "reopened"]);
const FIX_BRANCH_PREFIX = "jojox-fixes/";

// Oltre questo numero di file GitHub stesso smette di fornire i diff per una PR:
// è una guardia di sicurezza, non un limite che ci aspettiamo di raggiungere spesso.
const MAX_FILES_PER_PR = 3000;
// Quante richieste di contenuto file teniamo in volo insieme: abbastanza per
// essere veloci, abbastanza poco per non rischiare i rate limit "secondari" di
// GitHub su PR con centinaia di file.
const FILE_FETCH_CONCURRENCY = 8;

/** Esegue `fn` su ogni elemento con al massimo `limit` chiamate in parallelo. */
export async function mapWithConcurrency<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;
  async function worker(): Promise<void> {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i]);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}

export interface ChangedFile {
  filename: string;
  status: string;
  patch?: string;
}

/**
 * Elenca tutti i file cambiati in una PR, seguendo la paginazione di GitHub
 * (l'endpoint ne restituisce al massimo 100 per richiesta) fino a un tetto di
 * sicurezza: le PR con migliaia di file sono rarissime e comunque GitHub
 * stesso smette di fornire diff utili oltre una certa dimensione.
 */
export async function listChangedFiles(
  octokit: Pick<InstallationOctokit, "request">,
  params: { owner: string; repo: string; pull_number: number }
): Promise<ChangedFile[]> {
  const files: ChangedFile[] = [];
  for (let page = 1; files.length < MAX_FILES_PER_PR; page++) {
    const { data } = await octokit.request("GET /repos/{owner}/{repo}/pulls/{pull_number}/files", {
      ...params,
      per_page: 100,
      page,
    });
    files.push(...data);
    if (data.length < 100) break;
  }
  return files;
}

githubWebhookRouter.post("/webhooks/github", raw({ type: "application/json" }), async (req, res) => {
  const signature = req.header("x-hub-signature-256");
  const payload = req.body as Buffer;
  const rawBody = payload.toString("utf8");

  if (!verifyGithubSignature(rawBody, signature, env.githubWebhookSecret)) {
    res.status(401).json({ error: "Firma non valida" });
    return;
  }

  const event = req.header("x-github-event");
  const body = JSON.parse(rawBody);

  // Rispondiamo subito: GitHub considera lento (>10s) un webhook fallito.
  res.status(202).json({ received: true });

  try {
    if (event === "installation" && body.action === "created") {
      await recordInstallation(body as InstallationPayload);
    } else if (event === "pull_request" && HANDLED_PR_ACTIONS.has(body.action)) {
      await handlePullRequest(body as PullRequestPayload);
    }
  } catch (err) {
    console.error(`errore nell'elaborazione del webhook GitHub (${event})`, err);
  }
});

async function recordInstallation(body: InstallationPayload): Promise<void> {
  await supabaseAdmin.from("github_installations").upsert({
    installation_id: body.installation.id,
    account_login: body.installation.account.login,
    account_type: body.installation.account.type,
  });
}

async function handlePullRequest(body: PullRequestPayload): Promise<void> {
  const installationId = body.installation.id;
  const owner = body.repository.owner.login;
  const repo = body.repository.name;
  const pullNumber = body.pull_request.number;
  const headSha = body.pull_request.head.sha;
  const headBranch = body.pull_request.head.ref;

  const app = getGithubApp();
  const octokit = await app.getInstallationOctokit(installationId);

  const changedFiles = await listChangedFiles(octokit, { owner, repo, pull_number: pullNumber });

  // Ignoriamo i file rimossi (niente da analizzare) e quelli senza un "patch" testuale:
  // GitHub omette il patch per i file binari o troppo grandi per essere confrontati riga
  // per riga — provare comunque a leggerli come codice produrrebbe solo rumore o errori.
  const filesToAnalyze = changedFiles.filter((f) => f.status !== "removed" && f.patch !== undefined);

  const fetchedFiles = await mapWithConcurrency(filesToAnalyze, FILE_FETCH_CONCURRENCY, async (f): Promise<SourceFile | null> => {
    try {
      const { data } = await octokit.request("GET /repos/{owner}/{repo}/contents/{path}", {
        owner,
        repo,
        path: f.filename,
        ref: headSha,
      });
      // Sopra 1 MB l'API di GitHub non include il contenuto in base64: niente da leggere,
      // meglio saltare il file che analizzarlo a metà.
      if (!Array.isArray(data) && data.type === "file" && typeof data.content === "string" && data.size <= 1_000_000) {
        return { path: f.filename, content: Buffer.from(data.content, "base64").toString("utf8") };
      }
      return null;
    } catch (err) {
      console.error(`impossibile leggere ${f.filename} nella PR #${pullNumber} di ${owner}/${repo}`, err);
      return null;
    }
  });

  const files: SourceFile[] = fetchedFiles.filter((f): f is SourceFile => f !== null);

  const result = analyzeFiles(files);

  // Le stesse regole di correzione usate nell'analisi manuale, applicate qui
  // sui file della PR: se cambiano dei contenuti, li proponiamo come una PR
  // separata verso lo stesso branch, così chi ha aperto la PR resta libero
  // di accettarli o no invece di ritrovarsi commit non richiesti.
  const autofix = applyAutofixes(files);
  const changedForFix = files
    .map((original, i) => ({ original, fixed: autofix.files[i] }))
    .filter(({ original, fixed }) => fixed.content !== original.content)
    .map(({ fixed }) => fixed);

  let fixPrUrl: string | null = null;
  if (changedForFix.length > 0) {
    fixPrUrl = await openOrUpdateFixPr(octokit, {
      owner,
      repo,
      pullNumber,
      baseBranch: headBranch,
      headSha,
      changedFiles: changedForFix,
      fixedCheckIds: autofix.fixedCheckIds,
      filesChanged: autofix.filesChanged,
    });
  } else {
    await closeStaleFixPr(octokit, { owner, repo, pullNumber });
  }

  await octokit.request("POST /repos/{owner}/{repo}/check-runs", {
    owner,
    repo,
    name: "JoJoX security check",
    head_sha: headSha,
    status: "completed",
    conclusion: checkRunConclusion(result),
    output: {
      title: `Punteggio di sicurezza: ${result.score}/100`,
      summary: formatPrComment(result, fixPrUrl),
    },
  });

  await octokit.request("POST /repos/{owner}/{repo}/issues/{issue_number}/comments", {
    owner,
    repo,
    issue_number: pullNumber,
    body: formatPrComment(result, fixPrUrl),
  });

  const installation = await getInstallation(installationId);
  await supabaseAdmin.from("analyses").insert({
    user_id: installation?.installed_by ?? null,
    source: "github",
    repo_full_name: `${owner}/${repo}`,
    score: result.score,
    summary: result.summary,
    findings: result.findings,
  });

  const prUrl = `https://github.com/${owner}/${repo}/pull/${pullNumber}`;
  if (checkRunConclusion(result) === "failure") {
    await notifySlack(
      installation?.slack_webhook_url,
      `🛑 JoJoX ha bloccato una pull request su *${owner}/${repo}* (punteggio ${result.score}/100): ${prUrl}`
    );
  } else if (fixPrUrl) {
    await notifySlack(
      installation?.slack_webhook_url,
      `🔧 JoJoX ha proposto correzioni automatiche per una pull request su *${owner}/${repo}*: ${fixPrUrl}`
    );
  }
}

async function getInstallation(
  installationId: number
): Promise<{ installed_by: string | null; slack_webhook_url: string | null } | null> {
  const { data } = await supabaseAdmin
    .from("github_installations")
    .select("installed_by, slack_webhook_url")
    .eq("installation_id", installationId)
    .single();
  return data ?? null;
}

function fixPrBranchName(pullNumber: number): string {
  return `${FIX_BRANCH_PREFIX}${pullNumber}`;
}

function buildFixPrBody(fixedCheckIds: Set<string>, filesChanged: number): string {
  const titles = ALL_CHECKS.filter((c) => fixedCheckIds.has(c.id)).map((c) => `- ${c.title}`);
  return [
    `JoJoX ha corretto in automatico **${filesChanged}** ${filesChanged === 1 ? "file" : "file"} per **${fixedCheckIds.size}** ${fixedCheckIds.size === 1 ? "tipo di problema" : "tipi di problema"}:`,
    "",
    ...titles,
    "",
    "Nessun LLM: stesse regole usate dall'analisi, applicate in automatico. Controlla il diff prima di unire.",
  ].join("\n");
}

/**
 * Crea (o aggiorna, se esiste già da un push precedente sulla stessa PR) un
 * branch con solo le correzioni automatiche, e apre una PR verso il branch
 * della PR originale. Non tocca mai direttamente il branch dell'autore.
 */
async function openOrUpdateFixPr(
  octokit: InstallationOctokit,
  params: {
    owner: string;
    repo: string;
    pullNumber: number;
    baseBranch: string;
    headSha: string;
    changedFiles: SourceFile[];
    fixedCheckIds: Set<string>;
    filesChanged: number;
  }
): Promise<string> {
  const { owner, repo, pullNumber, baseBranch, headSha, changedFiles, fixedCheckIds, filesChanged } = params;
  const fixBranch = fixPrBranchName(pullNumber);

  const { data: tree } = await octokit.request("POST /repos/{owner}/{repo}/git/trees", {
    owner,
    repo,
    base_tree: headSha,
    tree: changedFiles.map((f) => ({ path: f.path, mode: "100644" as const, type: "blob" as const, content: f.content })),
  });

  const { data: commit } = await octokit.request("POST /repos/{owner}/{repo}/git/commits", {
    owner,
    repo,
    message: "JoJoX: correzioni automatiche",
    tree: tree.sha,
    parents: [headSha],
  });

  try {
    await octokit.request("PATCH /repos/{owner}/{repo}/git/refs/{ref}", {
      owner,
      repo,
      ref: `heads/${fixBranch}`,
      sha: commit.sha,
      force: true,
    });
  } catch {
    // Il branch di fix non esiste ancora per questa PR: lo creiamo.
    await octokit.request("POST /repos/{owner}/{repo}/git/refs", {
      owner,
      repo,
      ref: `refs/heads/${fixBranch}`,
      sha: commit.sha,
    });
  }

  const { data: existingPrs } = await octokit.request("GET /repos/{owner}/{repo}/pulls", {
    owner,
    repo,
    head: `${owner}:${fixBranch}`,
    state: "open",
  });
  if (existingPrs.length > 0) {
    return existingPrs[0].html_url;
  }

  const { data: newPr } = await octokit.request("POST /repos/{owner}/{repo}/pulls", {
    owner,
    repo,
    title: "JoJoX: correzioni automatiche",
    head: fixBranch,
    base: baseBranch,
    body: buildFixPrBody(fixedCheckIds, filesChanged),
  });
  return newPr.html_url;
}

/** Chiude ed elimina una PR/branch di fix rimasti da un push precedente, se ora non serve più. */
async function closeStaleFixPr(
  octokit: InstallationOctokit,
  params: { owner: string; repo: string; pullNumber: number }
): Promise<void> {
  const { owner, repo, pullNumber } = params;
  const fixBranch = fixPrBranchName(pullNumber);

  try {
    const { data: existingPrs } = await octokit.request("GET /repos/{owner}/{repo}/pulls", {
      owner,
      repo,
      head: `${owner}:${fixBranch}`,
      state: "open",
    });
    for (const pr of existingPrs) {
      await octokit.request("PATCH /repos/{owner}/{repo}/pulls/{pull_number}", {
        owner,
        repo,
        pull_number: pr.number,
        state: "closed",
      });
    }
    await octokit.request("DELETE /repos/{owner}/{repo}/git/refs/{ref}", {
      owner,
      repo,
      ref: `heads/${fixBranch}`,
    });
  } catch {
    // Non c'era nessuna PR/branch di fix da ripulire: va bene così.
  }
}