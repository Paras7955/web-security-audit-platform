import type { ReactNode } from "react";

type IconName =
  | "overview"
  | "target"
  | "scan"
  | "finding"
  | "intelligence"
  | "credential"
  | "operations"
  | "guide"
  | "sun"
  | "moon"
  | "refresh"
  | "search"
  | "trash"
  | "shield"
  | "check"
  | "arrow"
  | "activity";

export function AppIcon({ name, size = 18 }: { name: IconName; size?: number }) {
  const common = {
    width: size,
    height: size,
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 1.8,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
    "aria-hidden": true
  };

  const paths: Record<IconName, ReactNode> = {
    overview: <><rect x="3" y="3" width="7" height="7" rx="2" /><rect x="14" y="3" width="7" height="7" rx="2" /><rect x="3" y="14" width="7" height="7" rx="2" /><rect x="14" y="14" width="7" height="7" rx="2" /></>,
    target: <><circle cx="12" cy="12" r="8" /><circle cx="12" cy="12" r="3" /><path d="M12 2v3M12 19v3M2 12h3M19 12h3" /></>,
    scan: <><path d="M7 3H4a1 1 0 0 0-1 1v3M17 3h3a1 1 0 0 1 1 1v3M7 21H4a1 1 0 0 1-1-1v-3M17 21h3a1 1 0 0 0 1-1v-3" /><path d="m7 13 3 3 7-8" /></>,
    finding: <><path d="M12 3 3.5 19h17L12 3Z" /><path d="M12 9v4M12 16.5h.01" /></>,
    intelligence: <><path d="M9.5 3.7a8.5 8.5 0 1 0 9.6 3.2" /><path d="M14 2v6h6M8.5 13.5l2.2-2.2 1.8 1.8 3.8-4" /></>,
    credential: <><circle cx="8" cy="15" r="4" /><path d="m11 12 8-8M15 8l2 2M17 6l2 2" /></>,
    operations: <><path d="M4 7h10M18 7h2M4 17h2M10 17h10" /><circle cx="16" cy="7" r="2" /><circle cx="8" cy="17" r="2" /></>,
    guide: <><path d="M4 5.5A2.5 2.5 0 0 1 6.5 3H11v16H6.5A2.5 2.5 0 0 0 4 21.5v-16Z" /><path d="M20 5.5A2.5 2.5 0 0 0 17.5 3H13v16h4.5a2.5 2.5 0 0 1 2.5 2.5v-16Z" /></>,
    sun: <><circle cx="12" cy="12" r="4" /><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" /></>,
    moon: <path d="M20.2 15.3A8.5 8.5 0 0 1 8.7 3.8a8.5 8.5 0 1 0 11.5 11.5Z" />,
    refresh: <><path d="M20 7v5h-5" /><path d="M19 12a7 7 0 1 0-2 5" /></>,
    search: <><circle cx="11" cy="11" r="7" /><path d="m20 20-4-4" /></>,
    trash: <><path d="M4 7h16M9 7V4h6v3M7 7l1 14h8l1-14M10 11v6M14 11v6" /></>,
    shield: <><path d="M12 3 4.5 6v5.2c0 4.8 2.8 8.3 7.5 9.8 4.7-1.5 7.5-5 7.5-9.8V6L12 3Z" /><path d="m8.5 12 2.2 2.2 4.8-5" /></>,
    check: <path d="m5 12 4 4L19 6" />,
    arrow: <><path d="M5 12h14M14 7l5 5-5 5" /></>,
    activity: <path d="M3 12h4l2.5-6 5 12 2.5-6h4" />
  };

  return <svg {...common}>{paths[name]}</svg>;
}
