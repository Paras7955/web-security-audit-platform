import { readFileSync } from "node:fs";
import { join } from "node:path";

type Contracts = {
  scan_modes: string[];
  scan_statuses: string[];
  scan_steps: string[];
  default_limits: Record<string, number>;
};

function loadContracts(): Contracts {
  const candidates = [
    join(process.cwd(), "../shared/contracts.json"),
    join(process.cwd(), "shared/contracts.json"),
    join(process.cwd(), "../../shared/contracts.json")
  ];

  for (const candidate of candidates) {
    try {
      return JSON.parse(readFileSync(candidate, "utf-8")) as Contracts;
    } catch {
      // Try the next known local/Docker layout.
    }
  }

  throw new Error("Unable to locate shared/contracts.json");
}

const contracts = loadContracts();

export const SCAN_MODES = contracts.scan_modes;
export const SCAN_STATUSES = contracts.scan_statuses;
export const SCAN_STEPS = contracts.scan_steps;
export const DEFAULT_LIMITS = contracts.default_limits;
