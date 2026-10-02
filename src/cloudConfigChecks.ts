import type { Finding, FixExample } from "./types.js";

/**
 * Se un file caricato ha esattamente questo nome, non viene trattato come
 * codice sorgente: è lo snapshot dello stato IAM reale dell'account AWS
 * (vedi AWS_IAM_SNAPSHOT_COMMAND), e viene analizzato a parte.
 */
export const AWS_IAM_SNAPSHOT_FILENAME = "jojox-aws-iam-snapshot.json";

/**
 * Comando di sola lettura — nessuna scrittura possibile sull'account — da
 * lanciare in locale con le proprie credenziali AWS per ottenere lo
 * snapshot reale della configurazione IAM. Un'unica chiamata restituisce
 * già tutto (utenti, gruppi, ruoli, policy), senza bisogno di altri comandi
 * o di strumenti come jq.
 */
export const AWS_IAM_SNAPSHOT_COMMAND = `aws iam get-account-authorization-details --output json > ${AWS_IAM_SNAPSHOT_FILENAME}`;

const ADMINISTRATOR_ACCESS_ARN = "arn:aws:iam::aws:policy/AdministratorAccess";

interface IamStatement {
  Effect?: string;
  Action?: string | string[];
  Resource?: string | string[];
}

interface IamPolicyDocument {
  Statement?: IamStatement | IamStatement[];
}

interface InlinePolicy {
  PolicyName: string;
  PolicyDocument?: IamPolicyDocument;
}

interface AttachedManagedPolicy {
  PolicyArn: string;
}

interface UserDetail {
  UserName: string;
  AttachedManagedPolicies?: AttachedManagedPolicy[];
  UserPolicyList?: InlinePolicy[];
}

interface GroupDetail {
  GroupName: string;
  GroupPolicyList?: InlinePolicy[];
}

interface RoleDetail {
  RoleName: string;
  RolePolicyList?: InlinePolicy[];
}

interface ManagedPolicy {
  PolicyName: string;
  PolicyVersionList?: { Document?: IamPolicyDocument; IsDefaultVersion?: boolean }[];
}

export interface AwsIamSnapshot {
  UserDetailList?: UserDetail[];
  GroupDetailList?: GroupDetail[];
  RoleDetailList?: RoleDetail[];
  Policies?: ManagedPolicy[];
}

const SNAPSHOT_KEYS = ["UserDetailList", "GroupDetailList", "RoleDetailList", "Policies"] as const;

function isValidSnapshot(value: unknown): value is AwsIamSnapshot {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  // Basta che almeno uno dei campi attesi sia un array: un account con solo ruoli (senza utenti IAM) è legittimo.
  return SNAPSHOT_KEYS.some((key) => Array.isArray(v[key]));
}

/** Legge il file caricato dall'utente, generato da AWS_IAM_SNAPSHOT_COMMAND. */
export function parseAwsIamSnapshot(content: string): AwsIamSnapshot | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    return null;
  }
  return isValidSnapshot(parsed) ? parsed : null;
}

function statementsOf(doc: IamPolicyDocument | undefined): IamStatement[] {
  if (!doc?.Statement) return [];
  return Array.isArray(doc.Statement) ? doc.Statement : [doc.Statement];
}

function isWildcard(value: string | string[] | undefined): boolean {
  if (!value) return false;
  return Array.isArray(value) ? value.includes("*") : value === "*";
}

function hasFullAccessStatement(doc: IamPolicyDocument | undefined): boolean {
  return statementsOf(doc).some((s) => s.Effect === "Allow" && isWildcard(s.Action) && isWildcard(s.Resource));
}

function fixExample(before: string, after: string): FixExample {
  return { before, after };
}

function wildcardPolicyFinding(label: string, policyName: string): Finding {
  return {
    checkId: "aws-iam-wildcard-policy",
    severity: "high",
    confidence: "confirmed",
    title: `Policy IAM con accesso completo ("${policyName}" su ${label})`,
    description:
      'Verificato leggendo lo stato vero del tuo account AWS, non dedotto dal codice: questa policy ha uno statement con Effect "Allow", Action "*" e Resource "*" — concede accesso completo a ogni servizio e risorsa dell\'account. Può essere voluto per un ruolo di emergenza ("break-glass"), ma va confermato: per l\'uso quotidiano concedi solo i permessi davvero necessari (principio del privilegio minimo).',
    file: label,
    line: 0,
    snippet: `"${policyName}": Effect: Allow, Action: "*", Resource: "*"`,
    fix: fixExample(
      `{ "Effect": "Allow", "Action": "*", "Resource": "*" }`,
      `{ "Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::il-tuo-bucket/*" }`
    ),
  };
}

/**
 * A differenza degli altri controlli (che leggono codice sorgente e quindi
 * possono solo dedurre cosa succede a runtime), questi leggono lo stato vero
 * dell'account AWS: la confidenza sui fatti osservati è massima. Due
 * controlli, entrambi ricavati da un'unica chiamata di sola lettura
 * (aws iam get-account-authorization-details):
 * - policy con accesso completo (Action "*" + Resource "*"), su utenti,
 *   gruppi, ruoli o policy gestite dal cliente;
 * - utente IAM con la policy gestita da AWS "AdministratorAccess" collegata
 *   direttamente, invece che tramite un gruppo o un ruolo assumibile
 *   (violazione nota del CIS AWS Foundations Benchmark).
 */
export function awsIamConfigFindings(snapshot: AwsIamSnapshot): Finding[] {
  const findings: Finding[] = [];

  for (const user of snapshot.UserDetailList ?? []) {
    const label = `iam-user.${user.UserName}`;

    for (const policy of user.UserPolicyList ?? []) {
      if (hasFullAccessStatement(policy.PolicyDocument)) findings.push(wildcardPolicyFinding(label, policy.PolicyName));
    }

    if ((user.AttachedManagedPolicies ?? []).some((p) => p.PolicyArn === ADMINISTRATOR_ACCESS_ARN)) {
      findings.push({
        checkId: "aws-iam-admin-policy-on-user",
        severity: "high",
        confidence: "confirmed",
        title: `L'utente IAM "${user.UserName}" ha AdministratorAccess collegata direttamente`,
        description:
          'Verificato leggendo lo stato vero del tuo account AWS: questo utente ha la policy gestita da AWS "AdministratorAccess" collegata direttamente, invece che tramite un gruppo o un ruolo assumibile. Best practice AWS (CIS Benchmark): evitare privilegi di amministratore permanenti su un utente — usa un ruolo con credenziali temporanee per le operazioni che li richiedono davvero.',
        file: label,
        line: 0,
        snippet: `AttachedManagedPolicies: AdministratorAccess`,
        fix: fixExample(
          `Utente "${user.UserName}" → AdministratorAccess collegata direttamente`,
          `Utente "${user.UserName}" → nessuna policy diretta; AdministratorAccess solo su un ruolo assumibile quando serve davvero`
        ),
      });
    }
  }

  for (const group of snapshot.GroupDetailList ?? []) {
    const label = `iam-group.${group.GroupName}`;
    for (const policy of group.GroupPolicyList ?? []) {
      if (hasFullAccessStatement(policy.PolicyDocument)) findings.push(wildcardPolicyFinding(label, policy.PolicyName));
    }
  }

  for (const role of snapshot.RoleDetailList ?? []) {
    const label = `iam-role.${role.RoleName}`;
    for (const policy of role.RolePolicyList ?? []) {
      if (hasFullAccessStatement(policy.PolicyDocument)) findings.push(wildcardPolicyFinding(label, policy.PolicyName));
    }
  }

  for (const policy of snapshot.Policies ?? []) {
    const label = `iam-policy.${policy.PolicyName}`;
    const defaultVersion = (policy.PolicyVersionList ?? []).find((v) => v.IsDefaultVersion);
    if (hasFullAccessStatement(defaultVersion?.Document)) findings.push(wildcardPolicyFinding(label, policy.PolicyName));
  }

  return findings;
}