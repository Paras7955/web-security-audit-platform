export function ScopeHarborMark({ compact = false }: { compact?: boolean }) {
  return (
    <span className={compact ? "brandMark brandMarkCompact" : "brandMark"} aria-hidden="true">
      <svg viewBox="0 0 48 48" role="presentation">
        <defs>
          <linearGradient id="scopeharbor-mark-gradient" x1="7" y1="6" x2="41" y2="43" gradientUnits="userSpaceOnUse">
            <stop stopColor="#72F5D1" />
            <stop offset="0.48" stopColor="#31A7FF" />
            <stop offset="1" stopColor="#8B6BFF" />
          </linearGradient>
        </defs>
        <path
          d="M24 4.5 40 10v11.2c0 10.3-6.3 18.4-16 22.3-9.7-3.9-16-12-16-22.3V10l16-5.5Z"
          fill="url(#scopeharbor-mark-gradient)"
          opacity=".18"
        />
        <path
          d="M24 4.5 40 10v11.2c0 10.3-6.3 18.4-16 22.3-9.7-3.9-16-12-16-22.3V10l16-5.5Z"
          fill="none"
          stroke="url(#scopeharbor-mark-gradient)"
          strokeWidth="2.3"
          strokeLinejoin="round"
        />
        <circle cx="24" cy="22.5" r="8.5" fill="none" stroke="currentColor" strokeWidth="2" opacity=".92" />
        <path d="M24 14v4M24 27v4M15.5 22.5h4M28.5 22.5h4" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
        <circle cx="24" cy="22.5" r="2.4" fill="url(#scopeharbor-mark-gradient)" />
      </svg>
    </span>
  );
}
