/**
 * La Sentinella — il personaggio di JoJoX. Nasce dal nome già usato nel
 * prodotto (Sentinella 24/7, punto 21 della roadmap): un piccolo guardiano
 * che scansiona, non un'illustrazione decorativa a caso. Pensato per
 * comparire nell'hero oggi e diventare in futuro il volto della chat
 * (punto 19/25) — stessa identità, non due personaggi diversi.
 */
export function SentinelMascot({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 220 260"
      className={className}
      role="img"
      aria-label="La Sentinella di JoJoX"
    >
      <defs>
        <radialGradient id="sentinel-eye-glow" cx="50%" cy="42%" r="60%">
          <stop offset="0%" stopColor="#ffd98a" />
          <stop offset="55%" stopColor="var(--accent)" />
          <stop offset="100%" stopColor="var(--accent-soft)" />
        </radialGradient>
        <linearGradient id="sentinel-body-fill" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="var(--surface-muted)" />
          <stop offset="100%" stopColor="var(--surface)" />
        </linearGradient>
        <filter id="sentinel-beam-blur" x="-60%" y="-60%" width="220%" height="220%">
          <feGaussianBlur stdDeviation="3" />
        </filter>
      </defs>

      {/* base/ombra */}
      <ellipse cx="110" cy="242" rx="52" ry="9" fill="#000" opacity="0.35" />

      {/* gambe */}
      <g stroke="var(--border)" strokeWidth="3" fill="none">
        <path d="M86 198 L80 232" />
        <path d="M134 198 L140 232" />
      </g>
      <circle cx="80" cy="234" r="7" fill="var(--surface-muted)" stroke="var(--border)" strokeWidth="2" />
      <circle cx="140" cy="234" r="7" fill="var(--surface-muted)" stroke="var(--border)" strokeWidth="2" />

      {/* corpo */}
      <rect
        x="54"
        y="108"
        width="112"
        height="98"
        rx="26"
        fill="url(#sentinel-body-fill)"
        stroke="var(--border)"
        strokeWidth="2.5"
      />
      {/* dettaglio pannello sul petto, tipo terminale */}
      <rect x="80" y="150" width="60" height="30" rx="6" fill="var(--bg)" stroke="var(--border)" strokeWidth="1.5" />
      <line x1="88" y1="159" x2="118" y2="159" stroke="var(--accent-soft)" strokeWidth="2" strokeLinecap="round" />
      <line x1="88" y1="167" x2="132" y2="167" stroke="var(--border)" strokeWidth="2" strokeLinecap="round" />
      <line x1="88" y1="174" x2="108" y2="174" stroke="var(--border)" strokeWidth="2" strokeLinecap="round" />

      {/* braccia */}
      <g stroke="var(--border)" strokeWidth="3" fill="none" strokeLinecap="round">
        <path d="M54 130 Q30 140 28 172" className="sentinel-arm sentinel-arm-left" />
        <path d="M166 130 Q190 140 192 172" className="sentinel-arm sentinel-arm-right" />
      </g>
      <circle cx="28" cy="176" r="6" fill="var(--surface-muted)" stroke="var(--border)" strokeWidth="2" />
      <circle cx="192" cy="176" r="6" fill="var(--surface-muted)" stroke="var(--border)" strokeWidth="2" />

      {/* collo */}
      <rect x="100" y="94" width="20" height="18" fill="var(--surface)" stroke="var(--border)" strokeWidth="2" />

      {/* testa / cupola */}
      <path
        d="M62 90 Q62 38 110 34 Q158 38 158 90 Z"
        fill="url(#sentinel-body-fill)"
        stroke="var(--border)"
        strokeWidth="2.5"
      />

      {/* antenna */}
      <line x1="110" y1="34" x2="110" y2="14" stroke="var(--border)" strokeWidth="2.5" />
      <circle cx="110" cy="10" r="5" fill="var(--accent)" className="sentinel-antenna-blink" />

      {/* raggio di scansione, dietro l'occhio */}
      <g className="sentinel-scan-sweep" style={{ transformOrigin: "110px 66px" }}>
        <path d="M110 66 L40 66 L110 66 Z" fill="var(--accent)" opacity="0.14" filter="url(#sentinel-beam-blur)" />
      </g>

      {/* occhio */}
      <circle cx="110" cy="66" r="30" fill="var(--bg)" stroke="var(--border)" strokeWidth="2.5" />
      <circle cx="110" cy="66" r="21" fill="url(#sentinel-eye-glow)" className="sentinel-eye" />
      <circle cx="110" cy="66" r="21" fill="none" stroke="var(--accent-ink)" strokeOpacity="0.25" strokeWidth="1" />
      <circle cx="104" cy="59" r="4.5" fill="#fff" opacity="0.65" />
    </svg>
  );
}
