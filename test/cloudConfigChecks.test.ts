import { describe, expect, it } from "vitest";
import { analyzeFiles } from "../src/analyze.js";
import {
  AWS_IAM_SNAPSHOT_FILENAME,
  AWS_S3_SNAPSHOT_FILENAME,
  awsIamConfigFindings,
  awsS3ConfigFindings,
  parseAwsIamSnapshot,
  parseAwsS3Snapshot,
  type AwsIamSnapshot,
  type AwsS3Snapshot,
} from "../src/cloudConfigChecks.js";

const FULL_PAB = { PublicAccessBlockConfiguration: { BlockPublicAcls: true, IgnorePublicAcls: true, BlockPublicPolicy: true, RestrictPublicBuckets: true } };

function s3Snapshot(overrides: Partial<AwsS3Snapshot> = {}): AwsS3Snapshot {
  return { account: { accountPublicAccessBlock: FULL_PAB }, buckets: [], ...overrides };
}

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

describe("parseAwsS3Snapshot", () => {
  it("reads the account line and bucket lines (NDJSON, one JSON object per line)", () => {
    const lines = [
      JSON.stringify({ accountPublicAccessBlock: FULL_PAB }),
      JSON.stringify({ name: "my-bucket", policy: null, acl: null, publicAccessBlock: FULL_PAB }),
    ];
    const parsed = parseAwsS3Snapshot(lines.join("\n"));
    expect(parsed?.buckets).toHaveLength(1);
    expect(parsed?.buckets[0].name).toBe("my-bucket");
    expect(parsed?.account?.accountPublicAccessBlock).toEqual(FULL_PAB);
  });

  it("discards a malformed line instead of failing the whole file", () => {
    const lines = [JSON.stringify({ name: "good-bucket" }), "{ this is not valid json ::"];
    const parsed = parseAwsS3Snapshot(lines.join("\n"));
    expect(parsed?.buckets).toHaveLength(1);
    expect(parsed?.buckets[0].name).toBe("good-bucket");
  });

  it("ignores blank lines", () => {
    const parsed = parseAwsS3Snapshot(`${JSON.stringify({ name: "a" })}\n\n\n${JSON.stringify({ name: "b" })}\n`);
    expect(parsed?.buckets).toHaveLength(2);
  });

  it("returns null when the content has no recognizable JSON line at all", () => {
    expect(parseAwsS3Snapshot("not json\nstill not json\n")).toBeNull();
  });

  it("returns null for empty content", () => {
    expect(parseAwsS3Snapshot("")).toBeNull();
  });
});

describe("awsS3ConfigFindings", () => {
  it("flags a bucket made public by its bucket policy (wildcard Principal, Allow, no Condition)", () => {
    const findings = awsS3ConfigFindings(
      s3Snapshot({
        buckets: [
          {
            name: "public-policy",
            policy: { Statement: [{ Effect: "Allow", Principal: "*" }] },
            acl: { Grants: [] },
            publicAccessBlock: FULL_PAB,
          },
        ],
      })
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ checkId: "aws-s3-public-bucket-policy", severity: "critical", confidence: "confirmed", file: "s3.public-policy" });
  });

  it("also matches Principal as { AWS: '*' }", () => {
    const findings = awsS3ConfigFindings(
      s3Snapshot({
        buckets: [{ name: "b", policy: { Statement: [{ Effect: "Allow", Principal: { AWS: "*" } }] }, acl: { Grants: [] }, publicAccessBlock: FULL_PAB }],
      })
    );
    expect(findings.map((f) => f.checkId)).toContain("aws-s3-public-bucket-policy");
  });

  it("does not flag a wildcard Principal statement that has a restricting Condition", () => {
    const findings = awsS3ConfigFindings(
      s3Snapshot({
        buckets: [
          {
            name: "safe",
            policy: { Statement: [{ Effect: "Allow", Principal: "*", Condition: { StringEquals: { "aws:SourceVpce": "vpce-123" } } }] },
            acl: { Grants: [] },
            publicAccessBlock: FULL_PAB,
          },
        ],
      })
    );
    expect(findings.map((f) => f.checkId)).not.toContain("aws-s3-public-bucket-policy");
  });

  it("does not flag a policy with Effect Deny even with a wildcard Principal", () => {
    const findings = awsS3ConfigFindings(
      s3Snapshot({
        buckets: [{ name: "b", policy: { Statement: [{ Effect: "Deny", Principal: "*" }] }, acl: { Grants: [] }, publicAccessBlock: FULL_PAB }],
      })
    );
    expect(findings.map((f) => f.checkId)).not.toContain("aws-s3-public-bucket-policy");
  });

  it("flags a bucket made public by its ACL (AllUsers group)", () => {
    const findings = awsS3ConfigFindings(
      s3Snapshot({
        buckets: [
          {
            name: "public-acl",
            policy: null,
            acl: { Grants: [{ Grantee: { Type: "Group", URI: "http://acs.amazonaws.com/groups/global/AllUsers" }, Permission: "READ" }] },
            publicAccessBlock: FULL_PAB,
          },
        ],
      })
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ checkId: "aws-s3-public-bucket-acl", severity: "critical", file: "s3.public-acl" });
  });

  it("also flags the AuthenticatedUsers group", () => {
    const findings = awsS3ConfigFindings(
      s3Snapshot({
        buckets: [
          {
            name: "b",
            policy: null,
            acl: { Grants: [{ Grantee: { Type: "Group", URI: "http://acs.amazonaws.com/groups/global/AuthenticatedUsers" }, Permission: "READ" }] },
            publicAccessBlock: FULL_PAB,
          },
        ],
      })
    );
    expect(findings.map((f) => f.checkId)).toContain("aws-s3-public-bucket-acl");
  });

  it("does not flag an ACL granting access only to a CanonicalUser (the owner)", () => {
    const findings = awsS3ConfigFindings(
      s3Snapshot({
        buckets: [
          { name: "b", policy: null, acl: { Grants: [{ Grantee: { Type: "CanonicalUser" }, Permission: "FULL_CONTROL" }] }, publicAccessBlock: FULL_PAB },
        ],
      })
    );
    expect(findings).toHaveLength(0);
  });

  it("flags a bucket with Block Public Access disabled", () => {
    const findings = awsS3ConfigFindings(
      s3Snapshot({
        buckets: [
          {
            name: "no-block",
            policy: null,
            acl: { Grants: [] },
            publicAccessBlock: { PublicAccessBlockConfiguration: { BlockPublicAcls: true, IgnorePublicAcls: true, BlockPublicPolicy: false, RestrictPublicBuckets: true } },
          },
        ],
      })
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ checkId: "aws-s3-block-public-access-disabled", severity: "high", file: "s3.no-block" });
  });

  it("flags a bucket with Block Public Access never configured (null)", () => {
    const findings = awsS3ConfigFindings(s3Snapshot({ buckets: [{ name: "never-set", policy: null, acl: { Grants: [] }, publicAccessBlock: null }] }));
    expect(findings.map((f) => f.checkId)).toContain("aws-s3-block-public-access-disabled");
  });

  it("flags the account level when account-wide Block Public Access is disabled", () => {
    const findings = awsS3ConfigFindings(
      s3Snapshot({
        account: {
          accountPublicAccessBlock: { PublicAccessBlockConfiguration: { BlockPublicAcls: false, IgnorePublicAcls: true, BlockPublicPolicy: true, RestrictPublicBuckets: true } },
        },
      })
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ checkId: "aws-s3-block-public-access-disabled", file: "s3-account" });
  });

  it("does not flag the account level when it is null but no buckets exist (nothing to report)", () => {
    const findings = awsS3ConfigFindings({ account: null, buckets: [] });
    expect(findings).toHaveLength(0);
  });

  it("returns a clean, fully-protected account with no findings at all", () => {
    const findings = awsS3ConfigFindings(
      s3Snapshot({
        buckets: [
          { name: "clean", policy: null, acl: { Grants: [{ Grantee: { Type: "CanonicalUser" }, Permission: "FULL_CONTROL" }] }, publicAccessBlock: FULL_PAB },
        ],
      })
    );
    expect(findings).toHaveLength(0);
  });
});

describe("analyzeFiles with an AWS S3 snapshot file", () => {
  it("merges live-config findings with code findings and excludes the snapshot from code scanning", () => {
    const lines = [
      JSON.stringify({ accountPublicAccessBlock: FULL_PAB }),
      JSON.stringify({ name: "public-bucket", policy: { Statement: [{ Effect: "Allow", Principal: "*" }] }, acl: { Grants: [] }, publicAccessBlock: FULL_PAB }),
    ];
    const result = analyzeFiles([
      { path: "src/index.ts", content: 'const password = "hunter2super";' },
      { path: AWS_S3_SNAPSHOT_FILENAME, content: lines.join("\n") },
    ]);

    const checkIds = result.findings.map((f) => f.checkId).sort();
    expect(checkIds).toEqual(["aws-s3-public-bucket-policy", "hardcoded-secret"]);
  });

  it("ignores a snapshot with no recognizable line instead of throwing", () => {
    const result = analyzeFiles([{ path: AWS_S3_SNAPSHOT_FILENAME, content: "not valid at all" }]);
    expect(result.findings).toHaveLength(0);
    expect(result.score).toBe(100);
  });

  it("all three AWS snapshots (IAM, S3) and Supabase can be uploaded together", () => {
    const result = analyzeFiles([
      {
        path: "jojox-supabase-snapshot.json",
        content: JSON.stringify({ tables: [], policies: [], buckets: [{ id: "uploads", public: true }] }),
      },
      {
        path: AWS_IAM_SNAPSHOT_FILENAME,
        content: JSON.stringify({ UserDetailList: [{ UserName: "alice", AttachedManagedPolicies: [{ PolicyArn: "arn:aws:iam::aws:policy/AdministratorAccess" }] }] }),
      },
      {
        path: AWS_S3_SNAPSHOT_FILENAME,
        content: [JSON.stringify({ accountPublicAccessBlock: FULL_PAB }), JSON.stringify({ name: "b", policy: null, acl: { Grants: [] }, publicAccessBlock: null })].join("\n"),
      },
    ]);

    const checkIds = result.findings.map((f) => f.checkId).sort();
    expect(checkIds).toEqual(["aws-iam-admin-policy-on-user", "aws-s3-block-public-access-disabled", "supabase-live-public-bucket"]);
  });
});