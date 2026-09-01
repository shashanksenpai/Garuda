export default function BrandMark({ size = 20 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" className="brand-mark" aria-hidden="true">
      <path d="M12 2 L22 20 L12 15.5 L2 20 Z" fill="var(--accent)" opacity="0.92" />
      <path d="M12 2 L12 15.5 L2 20 Z" fill="var(--text)" opacity="0.16" />
    </svg>
  )
}
