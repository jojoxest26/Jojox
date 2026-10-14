/**
 * La Sentinella — il personaggio di JoJoX. Nasce dal nome già usato nel
 * prodotto (Sentinella 24/7, punto 21 della roadmap): un piccolo guardiano
 * che scansiona, non un'illustrazione decorativa a caso. Nell'hero si
 * affaccia dal bordo superiore del pannello di scansione, come se stesse
 * davvero sorvegliando il codice sotto di sé — pensato per diventare in
 * futuro anche il volto della chat (punto 19/25), stessa identità.
 */
export function SentinelMascot({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 140 108" className={className} role="img" aria-label="La Sentinella di JoJoX">
      <defs>
        <radialGradient id="sentinel-eye-glow" cx="42%" cy="38%" r="65%">
          <stop offset="0%" stopColor="#ffe6b0" />
          <stop offset="55%" stopColor="var(--accent)" />
          <stop offset="100%" stopColor="var(--accent-soft)" />
        </radialGradient>
        <linearGradient id="sentinel-body-fill" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#242933" />
          <stop offset="100%" stopColor="#1a1e25" />
        </linearGradient>
      </defs>

      {/* piccole "spalle", appena visibili sul bordo del pannello */}
      <rect x="24" y="86" width="92" height="22" rx="14" fill="url(#sentinel-body-fill)" stroke="#4a5262" strokeWidth="3" />

      {/* testa — grande, un solo occhio, proporzioni "chibi" */}
      <rect x="16" y="6" width="108" height="78" rx="38" fill="url(#sentinel-body-fill)" stroke="#4a5262" strokeWidth="3" />

      {/* antenna */}
      <line x1="70" y1="6" x2="70" y2="-8" stroke="#4a5262" strokeWidth="3" />
      <circle cx="70" cy="-10" r="6" fill="var(--accent)" className="sentinel-antenna-blink" />

      {/* raggio di scansione */}
      <g className="sentinel-scan-sweep" style={{ transformOrigin: "70px 46px" }}>
        <path d="M70 46 L4 46 L70 46 Z" fill="var(--accent)" opacity="0.12" />
      </g>

      {/* occhio, grande ed espressivo */}
      <circle cx="70" cy="46" r="31" fill="var(--bg)" stroke="#4a5262" strokeWidth="3" />
      <circle cx="70" cy="46" r="22" fill="url(#sentinel-eye-glow)" className="sentinel-eye" />
      <circle cx="61" cy="37" r="5" fill="#fff" opacity="0.75" />
      <circle cx="70" cy="46" r="7" fill="var(--accent-ink)" opacity="0.2" />
    </svg>
  );
}
