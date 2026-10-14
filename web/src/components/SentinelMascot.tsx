/**
 * La Sentinella — il personaggio di JoJoX. Nasce dal nome già usato nel
 * prodotto (Sentinella 24/7, punto 21 della roadmap): un piccolo guardiano
 * che scansiona, non un'illustrazione decorativa a caso. Punta il suo
 * scanner verso il pannello di codice — il raggio che ne esce è
 * letteralmente quello che JoJoX fa davvero. Pensato per diventare in
 * futuro anche il volto della chat (punto 19/25), stessa identità.
 */
export function SentinelMascot({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 260 320" className={className} role="img" aria-label="La Sentinella di JoJoX">
      <defs>
        <radialGradient id="sv-eye" cx="40%" cy="35%" r="65%">
          <stop offset="0%" stopColor="#fff3d6" />
          <stop offset="45%" stopColor="#ffcf6b" />
          <stop offset="75%" stopColor="var(--accent)" />
          <stop offset="100%" stopColor="var(--accent-soft)" />
        </radialGradient>
        <linearGradient id="sv-body" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stopColor="#30363f" />
          <stop offset="55%" stopColor="#20242c" />
          <stop offset="100%" stopColor="#15181e" />
        </linearGradient>
        <linearGradient id="sv-limb" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#2b3038" />
          <stop offset="100%" stopColor="#181b21" />
        </linearGradient>
        <radialGradient id="sv-emitter" cx="50%" cy="40%" r="60%">
          <stop offset="0%" stopColor="#fff7e6" />
          <stop offset="60%" stopColor="var(--accent)" />
          <stop offset="100%" stopColor="var(--accent-soft)" />
        </radialGradient>
        <linearGradient id="sv-beam" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%" stopColor="var(--accent)" stopOpacity="0.85" />
          <stop offset="100%" stopColor="var(--accent)" stopOpacity="0" />
        </linearGradient>
      </defs>

      {/* ombra a terra */}
      <ellipse cx="128" cy="308" rx="72" ry="10" fill="#000" opacity="0.4" />

      {/* piedi */}
      <rect x="78" y="286" width="30" height="16" rx="6" fill="url(#sv-limb)" stroke="#4a5262" strokeWidth="3" />
      <rect x="150" y="286" width="30" height="16" rx="6" fill="url(#sv-limb)" stroke="#4a5262" strokeWidth="3" />

      {/* gambe, leggermente divaricate per dare stabilità alla posa */}
      <rect x="82" y="224" width="26" height="66" rx="12" fill="url(#sv-limb)" stroke="#4a5262" strokeWidth="3" />
      <rect x="150" y="224" width="26" height="66" rx="12" fill="url(#sv-limb)" stroke="#4a5262" strokeWidth="3" />
      <rect x="82" y="224" width="26" height="14" rx="7" fill="#fff" opacity="0.04" />
      <rect x="150" y="224" width="26" height="14" rx="7" fill="#fff" opacity="0.04" />

      {/* braccio sinistro, rilassato lungo il fianco */}
      <path d="M78 150 q-30 10 -34 56" stroke="url(#sv-limb)" strokeWidth="24" strokeLinecap="round" fill="none" />
      <path d="M78 150 q-30 10 -34 56" stroke="#4a5262" strokeWidth="27" strokeLinecap="round" fill="none" opacity="0.0" />
      <circle cx="44" cy="208" r="15" fill="url(#sv-limb)" stroke="#4a5262" strokeWidth="3" />

      {/* corpo */}
      <rect x="62" y="140" width="136" height="100" rx="34" fill="url(#sv-body)" stroke="#4a5262" strokeWidth="3.5" />
      <rect x="62" y="140" width="136" height="30" rx="18" fill="#fff" opacity="0.035" />
      {/* pannello petto, come un piccolo terminale */}
      <rect x="92" y="172" width="76" height="40" rx="9" fill="var(--bg)" stroke="#4a5262" strokeWidth="2" />
      <line x1="102" y1="184" x2="148" y2="184" stroke="var(--accent)" strokeWidth="3" strokeLinecap="round" />
      <line x1="102" y1="194" x2="160" y2="194" stroke="#6b7482" strokeWidth="3" strokeLinecap="round" />
      <line x1="102" y1="203" x2="130" y2="203" stroke="#4a5262" strokeWidth="3" strokeLinecap="round" />

      {/* braccio destro, esteso in avanti a reggere lo scanner */}
      <path d="M186 158 Q 232 170 236 196" stroke="url(#sv-limb)" strokeWidth="26" strokeLinecap="round" fill="none" />
      {/* dispositivo scanner impugnato */}
      <g transform="translate(214 150)">
        <rect x="-14" y="-16" width="56" height="34" rx="9" fill="url(#sv-limb)" stroke="#4a5262" strokeWidth="3" />
        <circle cx="30" cy="1" r="13" fill="url(#sv-emitter)" className="sentinel-eye" />
        <circle cx="30" cy="1" r="13" fill="none" stroke="var(--accent-ink)" strokeOpacity="0.25" strokeWidth="1.5" />
      </g>

      {/* collo */}
      <rect x="112" y="124" width="36" height="22" fill="url(#sv-body)" stroke="#4a5262" strokeWidth="3" />

      {/* testa, grande, chibi, un solo occhio */}
      <rect x="40" y="18" width="180" height="128" rx="60" fill="url(#sv-body)" stroke="#4a5262" strokeWidth="3.5" />
      <rect x="40" y="18" width="180" height="40" rx="28" fill="#fff" opacity="0.04" />

      {/* antenna */}
      <line x1="130" y1="18" x2="130" y2="-10" stroke="#4a5262" strokeWidth="3.5" />
      <circle cx="130" cy="-14" r="9" fill="var(--accent)" className="sentinel-antenna-blink" />

      {/* raggio di scansione dell'occhio (sguardo), più sottile rispetto a quello dello scanner */}
      <g className="sentinel-scan-sweep" style={{ transformOrigin: "130px 82px" }}>
        <path d="M130 82 L30 82 L130 82 Z" fill="var(--accent)" opacity="0.1" />
      </g>

      {/* occhio */}
      <circle cx="130" cy="82" r="52" fill="var(--bg)" stroke="#4a5262" strokeWidth="4" />
      <circle cx="130" cy="82" r="52" fill="none" stroke="#000" strokeOpacity="0.3" strokeWidth="8" />
      <circle cx="130" cy="82" r="38" fill="url(#sv-eye)" className="sentinel-eye" />
      <circle cx="113" cy="65" r="10" fill="#fff" opacity="0.75" />
      <circle cx="130" cy="82" r="13" fill="var(--accent-ink)" opacity="0.18" />
    </svg>
  );
}
