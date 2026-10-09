import { analyzeFiles, applyAutofixes } from "../../analyze.js";
import { scanDependencies } from "../../depscan.js";
import { computeScore, summarizeBySeverity } from "../../scoring.js";
import type { Finding } from "../../types.js";
import { getGithubApp } from "../github/app.js";
import { listInstallationRepos, openAuditFixPr } from "../github/auditFixPr.js";
import { fetchRepoFiles } from "../github/repoContent.js";
import { supabaseAdmin } from "../db/supabase.js";
import { getPlanForUser } from "../plan.js";
import { notifySlack } from "../slack/notify.js";

// Un'installazione (specie su un'organizzazione) può avere centinaia di
// repository: un tetto di sicurezza per non far durare uno scan notturno
// all'infinito, non un limite che ci aspettiamo di raggiungere spesso.
const MAX_REPOS_PER_INSTALLATION = 200;

type InstallationOctokit = Awaited<ReturnType<Awaited<ReturnType<typeof getGithubApp>>["getInstallationOctokit"]>>;

/** Identifica in modo stabile un singolo finding, per confrontare uno scan con il precedente. */
export function findingKey(f: Finding): string {
  return `${f.checkId}:${f.file}:${f.line}`;
}

/**
 * Le chiavi presenti nello scan di oggi ma non in quello precedente.
 * `previous === null` significa "nessuno scan precedente per questo
 * repository" (prima connessione): in quel caso non c'è nulla di "nuovo" da
 * segnalare — altrimenti la prima notte dopo aver collegato un repository
 * già esistente manderebbe un avviso in blocco per ogni problema preesistente,
 * già visibile nella dashboard del sito.
 */
export function newFindingKeys(previous: string[] | null, current: string[]): string[] {
  if (previous === null) return [];
  const prevSet = new Set(previous);
  return current.filter((key) => !prevSet.has(key));
}

interface SentinelInstallation {
  installation_id: number;
  installed_by: string;
  slack_webhook_url: string | null;
}

/** Installazioni collegate a un account su un piano a pagamento (Pro o Team) — il monitoraggio continuo, come quello sulle pull request, non è una funzionalità del piano free. */
async function eligibleInstallations(): Promise<SentinelInstallation[]> {
  const { data } = await supabaseAdmin.from("github_installations").select("installation_id, installed_by, slack_webhook_url");

  const eligible: SentinelInstallation[] = [];
  for (const installation of data ?? []) {
    if (!installation.installed_by) continue;
    const plan = await getPlanForUser(installation.installed_by);
    if (plan === "free") continue;
    eligible.push(installation as SentinelInstallation);
  }
  return eligible;
}

async function scanRepo(
  octokit: InstallationOctokit,
  installation: SentinelInstallation,
  repo: { owner: string; repo: string; fullName: string }
): Promise<void> {
  const { files } = await fetchRepoFiles(octokit, { owner: repo.owner, repo: repo.repo });
  if (files.length === 0) return;

  const depFindings = await scanDependencies(files);
  const findings = [...analyzeFiles(files).findings, ...depFindings];
  const currentKeys = findings.map(findingKey);

  const { data: previousState } = await supabaseAdmin
    .from("repo_scan_state")
    .select("finding_keys")
    .eq("installation_id", installation.installation_id)
    .eq("repo_full_name", repo.fullName)
    .maybeSingle();

  const newKeys = new Set(newFindingKeys(previousState ? previousState.finding_keys : null, currentKeys));
  const newBlockingFindings = findings.filter((f, i) => newKeys.has(currentKeys[i]) && (f.severity === "critical" || f.severity === "high"));

  if (newBlockingFindings.length > 0) {
    let fixPrUrl: string | null = null;
    const autofix = applyAutofixes(files, { fullProject: true });
    if (autofix.changedFiles.length > 0) {
      try {
        fixPrUrl = await openAuditFixPr(octokit, {
          owner: repo.owner,
          repo: repo.repo,
          changedFiles: autofix.changedFiles,
          fixedCheckIds: autofix.fixedCheckIds,
          filesChanged: autofix.filesChanged,
        });
      } catch (err) {
        console.error(`Sentinella 24/7: impossibile aprire la pull request di correzione su ${repo.fullName}`, err);
      }
    }

    const repoUrl = `https://github.com/${repo.fullName}`;
    const prLine = fixPrUrl ? ` Ho aperto una pull request con le correzioni automatiche: ${fixPrUrl}` : "";
    await notifySlack(
      installation.slack_webhook_url,
      `🌙 La Sentinella 24/7 di JoJoX ha trovato ${newBlockingFindings.length} ${newBlockingFindings.length === 1 ? "nuovo problema critico o alto" : "nuovi problemi critici o alti"} su *${repo.fullName}*, non legati a nessuna pull request aperta: ${repoUrl}.${prLine}`
    );
  }

  const score = computeScore(findings);
  const summary = summarizeBySeverity(findings);

  await supabaseAdmin.from("repo_scan_state").upsert({
    installation_id: installation.installation_id,
    repo_full_name: repo.fullName,
    finding_keys: currentKeys,
    last_scanned_at: new Date().toISOString(),
  });

  await supabaseAdmin.from("analyses").insert({
    user_id: installation.installed_by,
    source: "sentinel",
    repo_full_name: repo.fullName,
    score,
    summary,
    findings,
  });
}

/**
 * Esegue lo scan notturno completo di ogni repository di ogni installazione
 * su un piano a pagamento: rilegge tutto il repository (non solo le pull
 * request aperte) e rilancia il controllo delle dipendenze — nuove
 * vulnerabilità su OSV.dev possono comparire anche senza nessun cambiamento
 * al codice. Un'installazione o un repository che falliscono non bloccano
 * gli altri: ognuno è isolato nel proprio try/catch.
 */
export async function runSentinelScan(): Promise<void> {
  const installations = await eligibleInstallations();
  const app = getGithubApp();

  for (const installation of installations) {
    try {
      const octokit = await app.getInstallationOctokit(installation.installation_id);
      const repos = (await listInstallationRepos(octokit)).slice(0, MAX_REPOS_PER_INSTALLATION);
      for (const repo of repos) {
        try {
          await scanRepo(octokit, installation, repo);
        } catch (err) {
          console.error(`Sentinella 24/7: errore nello scan di ${repo.fullName}`, err);
        }
      }
    } catch (err) {
      console.error(`Sentinella 24/7: errore sull'installazione ${installation.installation_id}`, err);
    }
  }
}
