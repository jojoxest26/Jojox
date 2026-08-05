import type { Check } from "../types.js";
import { criticalChecks } from "./critical.js";
import { highChecks } from "./high.js";
import { mediumChecks } from "./medium.js";
import { lowChecks } from "./low.js";

export const ALL_CHECKS: Check[] = [...criticalChecks, ...highChecks, ...mediumChecks, ...lowChecks];

if (new Set(ALL_CHECKS.map((c) => c.id)).size !== ALL_CHECKS.length) {
  throw new Error("Duplicate check id detected in ALL_CHECKS");
}

export { criticalChecks, highChecks, mediumChecks, lowChecks };
