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

/**
 * Se un file caricato ha esattamente questo nome, non viene trattato come
 * codice sorgente: è lo snapshot dello stato reale dei bucket S3
 * dell'account AWS (vedi AWS_S3_SNAPSHOT_SCRIPT), e viene analizzato a parte.
 */
export const AWS_S3_SNAPSHOT_FILENAME = "jojox-aws-s3-snapshot.ndjson";

/**
 * A differenza di IAM, S3 non ha un'unica chiamata che restituisca già tutto:
 * servono una chiamata per elenco bucket, poi policy/ACL/Block Public Access
 * per OGNUNO — un numero di bucket che varia da account ad account. Per
 * questo qui serve un piccolo script invece di un comando singolo, pensato
 * per restare semplice: produce un file con un oggetto JSON per riga
 * (formato NDJSON) invece di un unico blocco JSON, così non c'è bisogno di
 * gestire array/virgole a mano in bash — ogni riga si legge (o si scarta, se
 * malformata) per conto proprio. Tutte chiamate di sola lettura, nessuna
 * scrittura sull'account.
 */
export const AWS_S3_SNAPSHOT_SCRIPT = `ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
ACCOUNT_PAB=$(aws s3control get-public-access-block --account-id "$ACCOUNT_ID" --output json 2>/dev/null || echo null)
echo "{\\"accountPublicAccessBlock\\":$ACCOUNT_PAB}" > ${AWS_S3_SNAPSHOT_FILENAME}

for BUCKET in $(aws s3api list-buckets --query 'Buckets[].Name' --output text); do
  POLICY=$(aws s3api get-bucket-policy --bucket "$BUCKET" --query Policy --output text 2>/dev/null || echo null)
  ACL=$(aws s3api get-bucket-acl --bucket "$BUCKET" --output json 2>/dev/null || echo null)
  PAB=$(aws s3api get-public-access-block --bucket "$BUCKET" --output json 2>/dev/null || echo null)
  echo "{\\"name\\":\\"$BUCKET\\",\\"policy\\":$POLICY,\\"acl\\":$ACL,\\"publicAccessBlock\\":$PAB}" >> ${AWS_S3_SNAPSHOT_FILENAME}
done`;

interface S3PolicyStatement {
  Effect?: string;
  Principal?: string | { AWS?: string | string[] };
  Condition?: unknown;
}

interface S3BucketPolicy {
  Statement?: S3PolicyStatement | S3PolicyStatement[];
}

interface S3Grant {
  Grantee?: { Type?: string; URI?: string };
  Permission?: string;
}

interface S3BucketAcl {
  Grants?: S3Grant[];
}

interface PublicAccessBlockConfig {
  PublicAccessBlockConfiguration?: {
    BlockPublicAcls?: boolean;
    IgnorePublicAcls?: boolean;
    BlockPublicPolicy?: boolean;
    RestrictPublicBuckets?: boolean;
  };
}

interface S3BucketRecord {
  name: string;
  policy?: S3BucketPolicy | null;
  acl?: S3BucketAcl | null;
  publicAccessBlock?: PublicAccessBlockConfig | null;
}

interface AccountRecord {
  accountPublicAccessBlock?: PublicAccessBlockConfig | null;
}

export interface AwsS3Snapshot {
  account: AccountRecord | null;
  buckets: S3BucketRecord[];
}

/**
 * Legge il file NDJSON caricato dall'utente, generato da
 * AWS_S3_SNAPSHOT_SCRIPT: una riga per il blocco account, una per ogni
 * bucket. Una riga singola malformata (es. un nome di bucket con un
 * carattere che rompe il JSON costruito a mano in bash) viene scartata
 * invece di far fallire la lettura dell'intero file.
 */
export function parseAwsS3Snapshot(content: string): AwsS3Snapshot | null {
  let account: AccountRecord | null = null;
  const buckets: S3BucketRecord[] = [];
  let sawAnyLine = false;

  for (const rawLine of content.split("\n")) {
    const line = rawLine.trim();
    if (!line) continue;

    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      continue;
    }
    if (typeof parsed !== "object" || parsed === null) continue;
    sawAnyLine = true;

    const record = parsed as Record<string, unknown>;
    if ("accountPublicAccessBlock" in record) {
      account = record as AccountRecord;
    } else if (typeof record.name === "string") {
      buckets.push(record as unknown as S3BucketRecord);
    }
  }

  return sawAnyLine ? { account, buckets } : null;
}

const PUBLIC_ACL_GROUP_URI = /\/global\/(AllUsers|AuthenticatedUsers)$/;

function isPublicPolicyStatement(statement: S3PolicyStatement): boolean {
  if (statement.Effect !== "Allow") return false;
  if (statement.Condition) return false; // una Condition potrebbe restringere l'accesso — non proviamo a interpretarla, meglio un falso negativo
  const principal = statement.Principal;
  if (principal === "*") return true;
  if (typeof principal === "object" && principal !== null) {
    const aws = principal.AWS;
    if (aws === "*") return true;
    if (Array.isArray(aws) && aws.includes("*")) return true;
  }
  return false;
}

function isPublicGrant(grant: S3Grant): boolean {
  return !!grant.Grantee?.URI && PUBLIC_ACL_GROUP_URI.test(grant.Grantee.URI);
}

function isPublicAccessBlockDisabled(config: PublicAccessBlockConfig | null | undefined): boolean {
  const block = config?.PublicAccessBlockConfiguration;
  if (!block) return true; // mai configurato — trattato come se fosse disattivato
  return !block.BlockPublicAcls || !block.IgnorePublicAcls || !block.BlockPublicPolicy || !block.RestrictPublicBuckets;
}

/**
 * Tre controlli, tutti con confidenza massima perché leggono lo stato vero
 * dei bucket S3, non codice:
 * - bucket reso pubblico da una bucket policy (Effect "Allow", Principal "*",
 *   nessuna Condition restrittiva);
 * - bucket reso pubblico da un'ACL (grant al gruppo AllUsers o
 *   AuthenticatedUsers);
 * - Block Public Access disattivato (o mai configurato), a livello di
 *   account o del singolo bucket — un livello di protezione in meno, non
 *   necessariamente già sfruttato.
 */
export function awsS3ConfigFindings(snapshot: AwsS3Snapshot): Finding[] {
  const findings: Finding[] = [];

  // Controlliamo il livello account solo se il file caricato include davvero
  // quella riga: se manca del tutto (snapshot malformato o incompleto) non
  // inventiamo un finding — "nessun dato" non è lo stesso di "disattivato".
  if (snapshot.account && isPublicAccessBlockDisabled(snapshot.account.accountPublicAccessBlock)) {
    findings.push({
      checkId: "aws-s3-block-public-access-disabled",
      severity: "high",
      confidence: "confirmed",
      title: "Block Public Access non è attivo a livello di account AWS",
      description:
        "Verificato leggendo lo stato vero del tuo account AWS: il blocco account-wide per l'accesso pubblico a S3 non è completamente attivo (o non è mai stato configurato). Non significa che un bucket sia già pubblico, ma toglie una rete di sicurezza che impedirebbe di renderlo pubblico per errore in futuro — anche con un singolo bucket configurato male.",
      file: "s3-account",
      line: 0,
      snippet: "PublicAccessBlockConfiguration: non attivo su tutti e 4 i blocchi",
      fix: fixExample(
        "Block Public Access account-wide: non attivo",
        "aws s3control put-public-access-block --account-id <id> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
      ),
    });
  }

  for (const bucket of snapshot.buckets) {
    const label = `s3.${bucket.name}`;

    const statements = bucket.policy?.Statement
      ? Array.isArray(bucket.policy.Statement)
        ? bucket.policy.Statement
        : [bucket.policy.Statement]
      : [];
    if (statements.some(isPublicPolicyStatement)) {
      findings.push({
        checkId: "aws-s3-public-bucket-policy",
        severity: "critical",
        confidence: "confirmed",
        title: `Il bucket "${bucket.name}" è pubblico tramite la sua bucket policy`,
        description:
          "Verificato leggendo lo stato vero del tuo account AWS: la policy di questo bucket ha uno statement con Effect \"Allow\" e Principal \"*\" senza nessuna Condition che lo restringa — chiunque su internet può accedere secondo le azioni permesse da quello statement, senza bisogno di credenziali AWS.",
        file: label,
        line: 0,
        snippet: `Principal: "*", Effect: "Allow", nessuna Condition`,
        fix: fixExample(
          `"Principal": "*", "Effect": "Allow"`,
          `"Principal": { "AWS": "arn:aws:iam::<account>:role/<ruolo-che-deve-accedere>" }, "Effect": "Allow"`
        ),
      });
    }

    if ((bucket.acl?.Grants ?? []).some(isPublicGrant)) {
      findings.push({
        checkId: "aws-s3-public-bucket-acl",
        severity: "critical",
        confidence: "confirmed",
        title: `Il bucket "${bucket.name}" è pubblico tramite la sua ACL`,
        description:
          'Verificato leggendo lo stato vero del tuo account AWS: l\'ACL di questo bucket concede un permesso al gruppo "AllUsers" o "AuthenticatedUsers" — il primo significa chiunque su internet, il secondo chiunque abbia (o si crei) un account AWS qualsiasi, non necessariamente collegato al tuo.',
        file: label,
        line: 0,
        snippet: "Grantee: AllUsers/AuthenticatedUsers",
        fix: fixExample("Grantee: http://acs.amazonaws.com/groups/global/AllUsers", "ACL privata — nessun grant ai gruppi pubblici"),
      });
    }

    if (isPublicAccessBlockDisabled(bucket.publicAccessBlock)) {
      findings.push({
        checkId: "aws-s3-block-public-access-disabled",
        severity: "high",
        confidence: "confirmed",
        title: `Block Public Access non è attivo sul bucket "${bucket.name}"`,
        description:
          "Verificato leggendo lo stato vero del tuo account AWS: il blocco per l'accesso pubblico non è completamente attivo su questo bucket specifico (o non è mai stato configurato) — toglie una rete di sicurezza che impedirebbe di renderlo pubblico per errore in futuro.",
        file: label,
        line: 0,
        snippet: "PublicAccessBlockConfiguration: non attivo su tutti e 4 i blocchi",
        fix: fixExample(
          `Bucket "${bucket.name}": Block Public Access non attivo`,
          `aws s3api put-public-access-block --bucket ${bucket.name} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`
        ),
      });
    }
  }

  return findings;
}