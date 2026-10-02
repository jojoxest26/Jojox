import { describe, expect, it } from "vitest";
import { analyzeFiles } from "../src/analyze.js";
import {
  AWS_IAM_SNAPSHOT_FILENAME,
  awsIamConfigFindings,
  parseAwsIamSnapshot,
  type AwsIamSnapshot,
} from "../src/cloudConfigChecks.js";

function snapshot(overrides: Partial<AwsIamSnapshot> = {}): AwsIamSnapshot {
  return { UserDetailList: [], GroupDetailList: [], RoleDetailList: [], Policies: [], ...overrides };
}

const ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess";
const fullAccessDoc = { Statement: [{ Effect: "Allow", Action: "*", Resource: "*" }] };
const fullAccessDocArrays = { Statement: [{ Effect: "Allow", Action: ["*"], Resource: ["*"] }] };
const readOnlyDoc = { Statement: [{ Effect: "Allow", Action: "s3:GetObject", Resource: "arn:aws:s3:::bucket/*" }] };

describe("parseAwsIamSnapshot", () => {
  it("accepts the snapshot shape directly", () => {
    expect(parseAwsIamSnapshot(JSON.stringify(snapshot()))).toEqual(snapshot());
  });

  it("accepts a snapshot with only RoleDetailList populated (account with no IAM users)", () => {
    const s = { RoleDetailList: [{ RoleName: "x" }] };
    expect(parseAwsIamSnapshot(JSON.stringify(s))).toEqual(s);
  });

  it("returns null for invalid JSON", () => {
    expect(parseAwsIamSnapshot("{not json")).toBeNull();
  });

  it("returns null when none of the expected arrays are present", () => {
    expect(parseAwsIamSnapshot(JSON.stringify({ foo: "bar" }))).toBeNull();
  });
});

describe("awsIamConfigFindings", () => {
  it("flags a user with AdministratorAccess attached directly", () => {
    const findings = awsIamConfigFindings(
      snapshot({ UserDetailList: [{ UserName: "alice", AttachedManagedPolicies: [{ PolicyArn: ADMIN_ARN }] }] })
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      checkId: "aws-iam-admin-policy-on-user",
      severity: "high",
      confidence: "confirmed",
      file: "iam-user.alice",
    });
  });

  it("does not flag a user with a read-only managed policy", () => {
    const findings = awsIamConfigFindings(
      snapshot({
        UserDetailList: [{ UserName: "carol", AttachedManagedPolicies: [{ PolicyArn: "arn:aws:iam::aws:policy/ReadOnlyAccess" }] }],
      })
    );
    expect(findings).toHaveLength(0);
  });

  it("flags an inline user policy granting Action:* + Resource:*", () => {
    const findings = awsIamConfigFindings(
      snapshot({ UserDetailList: [{ UserName: "bob", UserPolicyList: [{ PolicyName: "Inline", PolicyDocument: fullAccessDoc }] }] })
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ checkId: "aws-iam-wildcard-policy", severity: "high", confidence: "confirmed", file: "iam-user.bob" });
    expect(findings[0].title).toContain("Inline");
  });

  it("also matches when Action/Resource are arrays containing '*'", () => {
    const findings = awsIamConfigFindings(
      snapshot({ UserDetailList: [{ UserName: "bob", UserPolicyList: [{ PolicyName: "Inline", PolicyDocument: fullAccessDocArrays }] }] })
    );
    expect(findings).toHaveLength(1);
  });

  it("does not flag a policy that only has a wildcard Resource but a specific Action", () => {
    const findings = awsIamConfigFindings(
      snapshot({
        RoleDetailList: [
          { RoleName: "safe-role", RolePolicyList: [{ PolicyName: "SafePolicy", PolicyDocument: { Statement: [{ Effect: "Allow", Action: "lambda:InvokeFunction", Resource: "*" }] } }] },
        ],
      })
    );
    expect(findings).toHaveLength(0);
  });

  it("does not flag a read-only inline policy", () => {
    const findings = awsIamConfigFindings(
      snapshot({ UserDetailList: [{ UserName: "carol", UserPolicyList: [{ PolicyName: "S3ReadOnly", PolicyDocument: readOnlyDoc }] }] })
    );
    expect(findings).toHaveLength(0);
  });

  it("flags a wildcard group policy", () => {
    const findings = awsIamConfigFindings(
      snapshot({ GroupDetailList: [{ GroupName: "Admins", GroupPolicyList: [{ PolicyName: "GroupWildcard", PolicyDocument: fullAccessDoc }] }] })
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ checkId: "aws-iam-wildcard-policy", file: "iam-group.Admins" });
  });

  it("flags a wildcard role policy", () => {
    const findings = awsIamConfigFindings(
      snapshot({ RoleDetailList: [{ RoleName: "danger-role", RolePolicyList: [{ PolicyName: "RoleWildcard", PolicyDocument: fullAccessDoc }] }] })
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ checkId: "aws-iam-wildcard-policy", file: "iam-role.danger-role" });
  });

  it("flags a customer-managed policy's default version granting full access", () => {
    const findings = awsIamConfigFindings(
      snapshot({
        Policies: [
          {
            PolicyName: "CustomFullAccess",
            PolicyVersionList: [
              { IsDefaultVersion: false, Document: readOnlyDoc },
              { IsDefaultVersion: true, Document: fullAccessDoc },
            ],
          },
        ],
      })
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ checkId: "aws-iam-wildcard-policy", file: "iam-policy.CustomFullAccess" });
  });

  it("ignores a non-default policy version even if it grants full access", () => {
    const findings = awsIamConfigFindings(
      snapshot({
        Policies: [
          {
            PolicyName: "OldVersionHadFullAccess",
            PolicyVersionList: [{ IsDefaultVersion: false, Document: fullAccessDoc }],
          },
        ],
      })
    );
    expect(findings).toHaveLength(0);
  });

  it("returns [] for a clean account with no users, groups, roles or custom policies", () => {
    expect(awsIamConfigFindings(snapshot())).toEqual([]);
  });
});

describe("analyzeFiles with an AWS IAM snapshot file", () => {
  it("merges live-config findings with code findings and excludes the snapshot from code scanning", () => {
    const result = analyzeFiles([
      { path: "src/index.ts", content: 'const password = "hunter2super";' },
      {
        path: AWS_IAM_SNAPSHOT_FILENAME,
        content: JSON.stringify(snapshot({ UserDetailList: [{ UserName: "alice", AttachedManagedPolicies: [{ PolicyArn: ADMIN_ARN }] }] })),
      },
    ]);

    const checkIds = result.findings.map((f) => f.checkId).sort();
    expect(checkIds).toEqual(["aws-iam-admin-policy-on-user", "hardcoded-secret"]);
  });

  it("ignores a malformed snapshot file instead of throwing", () => {
    const result = analyzeFiles([{ path: AWS_IAM_SNAPSHOT_FILENAME, content: "not valid json" }]);
    expect(result.findings).toHaveLength(0);
    expect(result.score).toBe(100);
  });

  it("both Supabase and AWS IAM snapshots can be uploaded together", () => {
    const result = analyzeFiles([
      {
        path: "jojox-supabase-snapshot.json",
        content: JSON.stringify({ tables: [{ schema: "public", name: "orders", rowsecurity: false }], policies: [], buckets: [] }),
      },
      {
        path: AWS_IAM_SNAPSHOT_FILENAME,
        content: JSON.stringify(snapshot({ UserDetailList: [{ UserName: "alice", AttachedManagedPolicies: [{ PolicyArn: ADMIN_ARN }] }] })),
      },
    ]);

    const checkIds = result.findings.map((f) => f.checkId).sort();
    expect(checkIds).toEqual(["aws-iam-admin-policy-on-user", "supabase-live-rls-disabled"]);
  });
});