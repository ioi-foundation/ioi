// Shared loading skeleton — source-derived from the bundle's animate-pulse loaders.
// Use instead of plain "Loading…" text so surfaces have premium loading states.
import "./Skeleton.css";

export function Skeleton({ w, h = 14, r = 6, className = "" }: { w?: number | string; h?: number | string; r?: number; className?: string }) {
  return (
    <span
      className={"sk " + className}
      style={{ width: w ?? "100%", height: h, borderRadius: r }}
      aria-hidden="true"
    />
  );
}

// A vertical stack of skeleton rows (e.g. list/table placeholders).
export function SkeletonRows({ rows = 5, className = "" }: { rows?: number; className?: string }) {
  return (
    <div className={"sk-rows " + className} role="status" aria-label="Loading" aria-busy="true">
      {Array.from({ length: rows }).map((_, i) => (
        <div className="sk-row" key={i}>
          <Skeleton w={28} h={28} r={8} />
          <div className="sk-row-lines">
            <Skeleton w={`${55 + ((i * 7) % 30)}%`} h={12} />
            <Skeleton w={`${30 + ((i * 5) % 25)}%`} h={10} />
          </div>
        </div>
      ))}
    </div>
  );
}
