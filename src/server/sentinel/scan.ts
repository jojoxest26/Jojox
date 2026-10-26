import { analyzeFiles, applyAutofixes } from "../../analyze.js";
import { scanDependencies } from "../../depscan.js";
import { computeScore, summarizeBySeverity } from "../../scoring.js";
import type { Finding } from "../../types.js";
import { getGithubApp } from "../github/app.js";
import { listInstallationRepos, openAuditFixPr } from "../github/auditFixPr.js";
import { fetchRepoFiles } from "../github/repoContent.js";
import { excludeSelfScanFixtures } from "../util/selfScanFixtures.js";
import { supabaseAdmin } from "../db/supabase.js";
import { getPlanForUser, type Plan } from "../plan.js";
import { notifySlack } from "../slack/notify.js";
import { notifyEmail, buildAlertEmailHtml } from "../email/notify.js";

// Un'installazione (specie su un'organizzazione) può avere centinaia di
// repository: un tetto di sicurezza per non far durare uno scan notturno
// all'infinito, non un limite che ci aspettiamo di raggiungere spesso.
const MAX_REPOS_PER_INSTALLATION = 200;

// Il piano Free include la Sentinella 24/7 gratis, ma solo su 1 repository —
// a pagamento (Pro/Team/Business) il tetto è quello generale sopra. Il
// repository monitorato è il primo restituito da GitHub per l'installazione,
// niente scelta manuale per ora.
const MAX_REPOS_PER_FREE_INSTALLATION = 1;

// Il Controllo h24 da solo (aziende, abbonamento a sé — vedi
// stripe/plans.ts) alza il tetto di un account altrimenti free fino a 25
// repository, senza sbloccare nient'altro del piano Business vero.
const MAX_REPOS_WITH_SENTINEL_ADDON = 25;

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
  ownerEmail: string | null;
  plan: Plan;
  sentinelAddonActive: boolean;
}

/**
 * Tutte le installazioni con un proprietario risolto — il piano free è
 * incluso (ha diritto alla Sentinella gratis su 1 repository), non è più un
 * filtro di eleggibilità ma solo decide (insieme al Controllo h24 da solo)
 * quanti repository della stessa installazione vengono controllati, in
 * runSentinelScan.
 */
async function eligibleInstallations(): Promise<SentinelInstallation[]> {
  const { data } = await supabaseAdmin.from("github_installations").select("installation_id, installed_by, slack_webhook_url");

  const eligible: SentinelInstallation[] = [];
  for (const installation of data ?? []) {
    if (!installation.installed_by) continue;
    const plan = await getPlanForUser(installation.installed_by);
    // Risolto una volta per installazione (non per repository): più
    // repository nella stessa installazione condividono lo stesso
    // proprietario, non ha senso richiederlo di nuovo ad ogni scanRepo.
    const { data: userData } = await supabaseAdmin.auth.admin.getUserById(installation.installed_by);
    const { data: profile } = await supabaseAdmin
      .from("profiles")
      .select("sentinel_addon_active")
      .eq("id", installation.installed_by)
      .single();
    eligible.push({
      ...installation,
      ownerEmail: userData.user?.email ?? null,
      plan,
      sentinelAddonActive: profile?.sentinel_addon_active ?? false,
    } as SentinelInstallation);
  }
  return eligible;
}

async function scanRepo(
  octokit: InstallationOctokit,
  installation: SentinelInstallation,
  repo: { owner: string; repo: string; fullName: string }
): Promise<void> {
  const { files: fetchedFiles } = await fetchRepoFiles(octokit, { owner: repo.owner, repo: repo.repo });
  const files = excludeSelfScanFixtures(fetchedFiles, repo.owner, repo.repo);
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
    const countLabel = newBlockingFindings.length === 1 ? "nuovo problema critico o alto" : "nuovi problemi critici o alti";
    await notifySlack(
      installation.slack_webhook_url,
      `🌙 La Sentinella 24/7 di JoJoX ha trovato ${newBlockingFindings.length} ${countLabel} su *${repo.fullName}*, non legati a nessuna pull request aperta: ${repoUrl}.${prLine}`
    );
    await notifyEmail(
      installation.ownerEmail,
      `JoJoX: ${newBlockingFindings.length} ${countLabel} su ${repo.fullName}`,
      buildAlertEmailHtml({
        title: `La Sentinella 24/7 ha trovato qualcosa di nuovo`,
        body: `${newBlockingFindings.length} ${countLabel} su <strong>${repo.fullName}</strong>, non legati a nessuna pull request aperta.${fixPrUrl ? " Ho già aperto una pull request con le correzioni automatiche." : ""}`,
        ctaLabel: fixPrUrl ? "Vedi la pull request" : "Vedi il repository",
        ctaUrl: fixPrUrl ?? repoUrl,
      })
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
      const repoCap =
        installation.plan !== "free"
          ? MAX_REPOS_PER_INSTALLATION
          : installation.sentinelAddonActive
            ? MAX_REPOS_WITH_SENTINEL_ADDON
            : MAX_REPOS_PER_FREE_INSTALLATION;
      const repos = (await listInstallationRepos(octokit)).slice(0, repoCap);
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
