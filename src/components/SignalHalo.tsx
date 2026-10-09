// ─── SignalHalo.tsx ──────────────────────────────────────────────────────────
// AURA's visual signature — a teal signal halo with six outer dots.
// Used in the sidebar brand mark. Purely decorative; aria-hidden on parent.

interface SignalHaloProps {
  size?: number;
  className?: string;
}

export function SignalHalo({ size = 36, className = '' }: SignalHaloProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 36 36"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      aria-hidden="true"
      focusable="false"
    >
      {/* Outer halo ring */}
      <circle cx="18" cy="18" r="16" stroke="#25A895" strokeWidth="1.5" opacity="0.25" />
      {/* Mid ring */}
      <circle cx="18" cy="18" r="11" stroke="#25A895" strokeWidth="1.5" opacity="0.5" />
      {/* Core */}
      <circle cx="18" cy="18" r="6" fill="#25A895" />
      {/* Six outer signal dots */}
      <circle cx="18" cy="2"  r="1.4" fill="#25A895" opacity="0.7" />
      <circle cx="18" cy="34" r="1.4" fill="#25A895" opacity="0.7" />
      <circle cx="2"  cy="18" r="1.4" fill="#25A895" opacity="0.7" />
      <circle cx="34" cy="18" r="1.4" fill="#25A895" opacity="0.7" />
      <circle cx="6"  cy="6"  r="1.2" fill="#25A895" opacity="0.45" />
      <circle cx="30" cy="30" r="1.2" fill="#25A895" opacity="0.45" />
    </svg>
  );
}
