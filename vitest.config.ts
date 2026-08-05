import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    env: {
      SUPABASE_URL: "http://localhost:54321",
      SUPABASE_SERVICE_ROLE_KEY: "test-service-role-key",
      GITHUB_APP_ID: "12345",
      GITHUB_APP_PRIVATE_KEY_BASE64: Buffer.from("test-private-key").toString("base64"),
      GITHUB_WEBHOOK_SECRET: "test-webhook-secret",
    },
  },
});
