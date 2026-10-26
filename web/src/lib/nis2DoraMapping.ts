// Mappatura delle regole di JoJoX alle aree di controllo richieste dalla
// Direttiva NIS2 (recepita in Italia con D.Lgs. 138/2024, art. 24) e dal
// Regolamento DORA (UE 2022/2554, direttamente applicabile): usata solo nel
// report Aziendale (990€), mai in quello standard (99€) — è questo il vero
// differenziatore tra i due audit, non un limite di file più alto.
//
// Le citazioni restano nella lingua ufficiale dei testi normativi
// (italiano per il D.Lgs. di recepimento NIS2, che è quello rilevante per
// le aziende italiane; gli articoli DORA sono numerati identicamente in
// tutte le lingue del regolamento UE) indipendentemente dalla lingua
// dell'interfaccia: è la convenzione dei report di compliance, e un
// riferimento legale tradotto liberamente rischierebbe di confondere chi
// lo deve mostrare al proprio referente NIS2/DORA.
//
// Importante: questa mappatura è un supporto tecnico all'autovalutazione,
// non una certificazione di conformità legale — il report lo dice esplicitamente.

export interface ComplianceDomain {
  id: string;
  label: string;
  nis2: string;
  dora: string;
}

export const COMPLIANCE_DOMAINS: Record<string, ComplianceDomain> = {
  secrets: {
    id: "secrets",
    label: "Gestione dei segreti e delle credenziali",
    nis2: "NIS2 — D.Lgs. 138/2024, art. 24, c. 2, lett. i)",
    dora: "DORA — Reg. UE 2022/2554, art. 9",
  },
  accessControl: {
    id: "accessControl",
    label: "Controllo degli accessi e gestione delle identità",
    nis2: "NIS2 — D.Lgs. 138/2024, art. 24, c. 2, lett. i)",
    dora: "DORA — Reg. UE 2022/2554, art. 9",
  },
  cryptography: {
    id: "cryptography",
    label: "Crittografia e protezione dei dati",
    nis2: "NIS2 — D.Lgs. 138/2024, art. 24, c. 2, lett. h)",
    dora: "DORA — Reg. UE 2022/2554, art. 9, par. 3",
  },
  network: {
    id: "network",
    label: "Sicurezza delle reti e dei sistemi informativi",
    nis2: "NIS2 — D.Lgs. 138/2024, art. 24, c. 2, lett. c)",
    dora: "DORA — Reg. UE 2022/2554, art. 13",
  },
  injection: {
    id: "injection",
    label: "Protezione dalle intrusioni applicative",
    nis2: "NIS2 — D.Lgs. 138/2024, art. 24, c. 2, lett. c)",
    dora: "DORA — Reg. UE 2022/2554, art. 9",
  },
  supplyChain: {
    id: "supplyChain",
    label: "Sicurezza della catena di approvvigionamento",
    nis2: "NIS2 — D.Lgs. 138/2024, art. 24, c. 2, lett. d)",
    dora: "DORA — Reg. UE 2022/2554, art. 28",
  },
  incidentLogging: {
    id: "incidentLogging",
    label: "Gestione degli incidenti e rilevamento",
    nis2: "NIS2 — D.Lgs. 138/2024, art. 23",
    dora: "DORA — Reg. UE 2022/2554, artt. 17-19",
  },
  resilience: {
    id: "resilience",
    label: "Continuità operativa e resilienza dei sistemi",
    nis2: "NIS2 — D.Lgs. 138/2024, art. 24, c. 2, lett. b)",
    dora: "DORA — Reg. UE 2022/2554, artt. 11-12",
  },
  riskManagement: {
    id: "riskManagement",
    label: "Gestione del rischio",
    nis2: "NIS2 — D.Lgs. 138/2024, art. 24, c. 2, lett. a)",
    dora: "DORA — Reg. UE 2022/2554, art. 6",
  },
};

const CHECK_ID_TO_DOMAIN: Record<string, string> = {
  // Segreti e credenziali
  "hardcoded-secret": "secrets",
  "env-file-with-real-values": "secrets",
  "docker-hardcoded-secret": "secrets",
  "k8s-plaintext-secret-env": "secrets",
  "terraform-hardcoded-secret": "secrets",
  "hardcoded-jwt-secret": "secrets",

  // Controllo accessi e identità
  "supabase-service-role-in-client": "accessControl",
  "missing-row-level-security": "accessControl",
  "unprotected-new-table": "accessControl",
  "admin-function-missing-auth": "accessControl",
  idor: "accessControl",
  "k8s-privileged-container": "accessControl",
  "k8s-privilege-escalation": "accessControl",
  "k8s-run-as-root": "accessControl",
  "k8s-host-namespace-access": "accessControl",
  "terraform-iam-wildcard-policy": "accessControl",
  "gcp-iam-overly-broad-role": "accessControl",
  "azure-role-assignment-owner": "accessControl",
  "gha-excessive-permissions": "accessControl",

  // Crittografia e protezione dati
  "plaintext-password-storage": "cryptography",
  "weak-password-hashing": "cryptography",
  "jwt-none-algorithm": "cryptography",
  "insecure-token-storage": "cryptography",
  "insecure-cookie-flags": "cryptography",
  "weak-random-token": "cryptography",

  // Sicurezza di rete ed esposizione
  "terraform-open-security-group": "network",
  "gcp-firewall-open-to-internet": "network",
  "azure-nsg-open-to-internet": "network",
  "permissive-cors": "network",
  ssrf: "network",
  "public-storage-bucket": "network",
  "gcp-storage-bucket-public": "network",
  "azure-storage-public-access": "network",
  "open-redirect": "network",
  "header-injection": "network",

  // Intrusioni applicative
  "sql-injection": "injection",
  "nosql-injection": "injection",
  "command-injection": "injection",
  ssti: "injection",
  xxe: "injection",
  "ldap-injection": "injection",
  "xss-dangerous-html": "injection",
  "csrf-state-changing-get": "injection",
  "path-traversal": "injection",

  // Catena di approvvigionamento (CI/CD, dipendenze, container)
  "vulnerable-dependency": "supplyChain",
  "dependency-scan-unpinned-skipped": "supplyChain",
  "docker-unpinned-base-image": "supplyChain",
  "docker-add-remote-url": "supplyChain",
  "gha-unpinned-action": "supplyChain",
  "gha-script-injection": "supplyChain",
  "gha-pull-request-target-checkout": "supplyChain",
  "gitlab-ci-unpinned-image": "supplyChain",
  "gitlab-ci-script-injection": "supplyChain",
  "gitlab-ci-privileged-dind-no-tls": "supplyChain",
  "circleci-unpinned-image": "supplyChain",
  "circleci-pipeline-parameter-injection": "supplyChain",
  "circleci-add-ssh-keys-no-fingerprint": "supplyChain",
  "insecure-deserialization": "supplyChain",

  // Incidenti e rilevamento
  "sensitive-data-in-logs": "incidentLogging",
  "no-login-rate-limit": "incidentLogging",

  // Continuità e resilienza
  "docker-missing-user": "resilience",
  "k8s-missing-run-as-non-root": "resilience",
};

/** Area di controllo NIS2/DORA cui appartiene una regola — ricadenza su "gestione del rischio" per qualunque checkId non ancora mappato esplicitamente. */
export function complianceDomainForCheckId(checkId: string): ComplianceDomain {
  const domainId = CHECK_ID_TO_DOMAIN[checkId] ?? "riskManagement";
  return COMPLIANCE_DOMAINS[domainId]!;
}
