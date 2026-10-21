import { Router } from "express";
import { z } from "zod";
import type { Severity } from "../../types.js";
import { createIpRateLimit } from "../util/rateLimit.js";

const MAX_FINDINGS_RETURNED = 300;

const requestSchema = z.object({
  sarif: z.string().min(2).max(10_000_000),
});

interface SarifFinding {
  ruleId: string;
  severity: Severity;
  message: string;
  file: string | null;
  line: number | null;
}

export interface SarifImportResult {
  toolName: string | null;
  totalFindings: number;
  returnedFindings: number;
  bySeverity: Record<Severity, number>;
  findings: SarifFinding[];
}

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];

function severityFromSecurityScore(score: number): Severity {
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  return "low";
}

function severityFromLevel(level: unknown): Severity {
  switch (level) {
    case "error":
      return "high";
    case "warning":
      return "medium";
    default:
      return "low";
  }
}

/**
 * Parser SARIF volutamente permissivo: i tool reali (Snyk Code, Semgrep,
 * CodeQL/GitHub code scanning...) seguono lo schema in modo leggermente
 * diverso l'uno dall'altro, quindi ogni campo è letto con optional chaining
 * e un fallback, mai assunto presente.
 */
/**
 * Codici d'errore machine-readable, mai testo in italiano: il frontend ha
 * già una stringa tradotta in tutte le 23 lingue per ciascuno di questi, e
 * deve restare lui a scegliere quale mostrare in base alla lingua di chi
 * visita il sito.
 */
export type SarifImportErrorCode = "invalid_sarif" | "invalid_json";

export function parseSarif(doc: unknown): SarifImportResult | { errorCode: SarifImportErrorCode } {
  if (typeof doc !== "object" || doc === null || !Array.isArray((doc as { runs?: unknown }).runs)) {
    return { errorCode: "invalid_sarif" };
  }

  const runs = (doc as { runs: unknown[] }).runs;
  const findings: SarifFinding[] = [];
  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  let toolName: string | null = null;
  let totalFindings = 0;

  for (const run of runs) {
    const r = run as Record<string, unknown>;
    const tool = r.tool as Record<string, unknown> | undefined;
    const driver = tool?.driver as Record<string, unknown> | undefined;
    if (!toolName && typeof driver?.name === "string") toolName = driver.name;

    const rulesById = new Map<string, Record<string, unknown>>();
    const rules = Array.isArray(driver?.rules) ? (driver!.rules as unknown[]) : [];
    for (const rule of rules) {
      const rr = rule as Record<string, unknown>;
      if (typeof rr.id === "string") rulesById.set(rr.id, rr);
    }

    const results = Array.isArray(r.results) ? (r.results as unknown[]) : [];
    for (const result of results) {
      totalFindings++;
      const res = result as Record<string, unknown>;
      const ruleId = typeof res.ruleId === "string" ? res.ruleId : "unknown";
      const rule = rulesById.get(ruleId);
      const properties = rule?.properties as Record<string, unknown> | undefined;

      let severity: Severity;
      const rawScore = properties?.["security-severity"];
      const score = typeof rawScore === "string" ? Number(rawScore) : typeof rawScore === "number" ? rawScore : NaN;
      severity = Number.isNaN(score) ? severityFromLevel(res.level) : severityFromSecurityScore(score);
      bySeverity[severity]++;

      if (findings.length < MAX_FINDINGS_RETURNED) {
        const message = res.message as Record<string, unknown> | undefined;
        const shortDescription = rule?.shortDescription as Record<string, unknown> | undefined;
        const text =
          typeof message?.text === "string"
            ? message.text
            : typeof shortDescription?.text === "string"
              ? shortDescription.text
              : ruleId;

        const locations = Array.isArray(res.locations) ? (res.locations as unknown[]) : [];
        const physicalLocation = (locations[0] as Record<string, unknown> | undefined)?.physicalLocation as
          | Record<string, unknown>
          | undefined;
        const artifactLocation = physicalLocation?.artifactLocation as Record<string, unknown> | undefined;
        const region = physicalLocation?.region as Record<string, unknown> | undefined;
        const file = typeof artifactLocation?.uri === "string" ? artifactLocation.uri : null;
        const line = typeof region?.startLine === "number" ? region.startLine : null;

        findings.push({ ruleId, severity, message: text, file, line });
      }
    }
  }

  findings.sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));

  return { toolName, totalFindings, returnedFindings: findings.length, bySeverity, findings };
}

export const sarifImportRouter = Router();

// Punto 18 quinquies: unica rotta davvero pubblica (nessun login, nessun
// credito da consumare) che fa comunque un lavoro non banale — il parsing
// di un JSON arbitrario fino a 10MB — quindi è quella con più bisogno di un
// tetto per IP contro l'uso automatizzato eccessivo, a differenza di
// /api/analyze-audit (richiede login + un credito pagato) o del server MCP
// (gira in locale sulla macchina di chi lo usa, non tocca questo server).
const sarifImportRateLimit = createIpRateLimit({
  windowMs: 10 * 60 * 1000,
  max: 20,
  message: "Troppe richieste di import SARIF da questo indirizzo IP — riprova tra qualche minuto.",
});

// Pubblica, senza login: fa solo da lead magnet per chi arriva da un altro
// strumento, nessuna chiamata AI né scrittura su database.
sarifImportRouter.post("/api/sarif-import", sarifImportRateLimit, (req, res) => {
  const parsed = requestSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ errorCode: "invalid_sarif" });
    return;
  }

  let doc: unknown;
  try {
    doc = JSON.parse(parsed.data.sarif);
  } catch {
    res.status(400).json({ errorCode: "invalid_json" });
    return;
  }

  const result = parseSarif(doc);
  if ("errorCode" in result) {
    res.status(400).json(result);
    return;
  }

  res.json(result);
});
