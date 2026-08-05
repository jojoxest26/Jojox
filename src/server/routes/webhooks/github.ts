import { Router, raw } from "express";
import { env } from "../../env.js";
import { verifyGithubSignature } from "../../github/verifySignature.js";
import { getGithubApp } from "../../github/app.js";
import { analyzeFiles } from "../../../analyze.js";
import { checkRunConclusion, formatPrComment } from "../../github/report.js";
import { supabaseAdmin } from "../../db/supabase.js";
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
  pull_request: { number: number; head: { sha: string } };
}

export const githubWebhookRouter = Router();

const HANDLED_PR_ACTIONS = new Set(["opened", "synchronize", "reopened"]);

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

  const app = getGithubApp();
  const octokit = await app.getInstallationOctokit(installationId);

  const { data: changedFiles } = await octokit.request(
    "GET /repos/{owner}/{repo}/pulls/{pull_number}/files",
    { owner, repo, pull_number: pullNumber, per_page: 100 }
  );

  const files: SourceFile[] = await Promise.all(
    changedFiles
      .filter((f) => f.status !== "removed")
      .map(async (f): Promise<SourceFile> => {
        const { data } = await octokit.request("GET /repos/{owner}/{repo}/contents/{path}", {
          owner,
          repo,
          path: f.filename,
          ref: headSha,
        });
        const content =
          !Array.isArray(data) && data.type === "file" && typeof data.content === "string"
            ? Buffer.from(data.content, "base64").toString("utf8")
            : "";
        return { path: f.filename, content };
      })
  );

  const result = analyzeFiles(files);

  await octokit.request("POST /repos/{owner}/{repo}/check-runs", {
    owner,
    repo,
    name: "JoJoX security check",
    head_sha: headSha,
    status: "completed",
    conclusion: checkRunConclusion(result),
    output: {
      title: `Punteggio di sicurezza: ${result.score}/100`,
      summary: formatPrComment(result),
    },
  });

  await octokit.request("POST /repos/{owner}/{repo}/issues/{issue_number}/comments", {
    owner,
    repo,
    issue_number: pullNumber,
    body: formatPrComment(result),
  });

  const installedBy = await getInstalledByUserId(installationId);
  await supabaseAdmin.from("analyses").insert({
    user_id: installedBy,
    source: "github",
    repo_full_name: `${owner}/${repo}`,
    score: result.score,
    summary: result.summary,
    findings: result.findings,
  });
}

async function getInstalledByUserId(installationId: number): Promise<string | null> {
  const { data } = await supabaseAdmin
    .from("github_installations")
    .select("installed_by")
    .eq("installation_id", installationId)
    .single();
  return data?.installed_by ?? null;
}
