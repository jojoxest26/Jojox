import { describe, expect, it } from "vitest";
import { analyzeFiles } from "../src/analyze.js";
import {
  SUPABASE_SNAPSHOT_FILENAME,
  parseSupabaseSnapshot,
  supabaseConfigFindings,
  type SupabaseSchemaSnapshot,
} from "../src/supabaseConfigChecks.js";

function snapshot(overrides: Partial<SupabaseSchemaSnapshot> = {}): SupabaseSchemaSnapshot {
  return { tables: [], policies: [], buckets: [], ...overrides };
}

describe("parseSupabaseSnapshot", () => {
  it("accepts the snapshot shape directly", () => {
    const parsed = parseSupabaseSnapshot(JSON.stringify(snapshot()));
    expect(parsed).toEqual(snapshot());
  });

  it("unwraps the jojox_snapshot column Supabase exports for a single-row result", () => {
    const parsed = parseSupabaseSnapshot(JSON.stringify({ jojox_snapshot: snapshot() }));
    expect(parsed).toEqual(snapshot());
  });

  it("returns null for invalid JSON", () => {
    expect(parseSupabaseSnapshot("{not json")).toBeNull();
  });

  it("returns null when required arrays are missing", () => {
    expect(parseSupabaseSnapshot(JSON.stringify({ tables: [] }))).toBeNull();
  });
});

describe("supabaseConfigFindings", () => {
  it("flags a table with RLS disabled as critical and confirmed", () => {
    const findings = supabaseConfigFindings(
      snapshot({ tables: [{ schema: "public", name: "orders", rowsecurity: false }] })
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      checkId: "supabase-live-rls-disabled",
      severity: "critical",
      confidence: "confirmed",
      file: "public.orders",
    });
  });

  it("flags RLS enabled with zero policies as a heuristic medium finding", () => {
    const findings = supabaseConfigFindings(
      snapshot({ tables: [{ schema: "public", name: "profiles", rowsecurity: true }] })
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ checkId: "supabase-live-rls-no-policies", severity: "medium", confidence: "heuristic" });
  });

  it("does not flag a table with RLS enabled and at least one policy", () => {
    const findings = supabaseConfigFindings(
      snapshot({
        tables: [{ schema: "public", name: "profiles", rowsecurity: true }],
        policies: [{ schema: "public", table: "profiles", name: "owners only" }],
      })
    );
    expect(findings).toHaveLength(0);
  });

  it("flags a public storage bucket", () => {
    const findings = supabaseConfigFindings(snapshot({ buckets: [{ id: "uploads", public: true }] }));
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ checkId: "supabase-live-public-bucket", severity: "medium", confidence: "confirmed" });
  });

  it("does not flag a private storage bucket", () => {
    const findings = supabaseConfigFindings(snapshot({ buckets: [{ id: "uploads", public: false }] }));
    expect(findings).toHaveLength(0);
  });
});

describe("analyzeFiles with a Supabase snapshot file", () => {
  it("merges live-config findings with code findings and excludes the snapshot from code scanning", () => {
    const result = analyzeFiles([
      { path: "src/index.ts", content: 'const password = "hunter2super";' },
      {
        path: SUPABASE_SNAPSHOT_FILENAME,
        content: JSON.stringify(snapshot({ tables: [{ schema: "public", name: "orders", rowsecurity: false }] })),
      },
    ]);

    const checkIds = result.findings.map((f) => f.checkId).sort();
    expect(checkIds).toEqual(["hardcoded-secret", "supabase-live-rls-disabled"]);
  });

  it("ignores a malformed snapshot file instead of throwing", () => {
    const result = analyzeFiles([{ path: SUPABASE_SNAPSHOT_FILENAME, content: "not valid json" }]);
    expect(result.findings).toHaveLength(0);
    expect(result.score).toBe(100);
  });
});