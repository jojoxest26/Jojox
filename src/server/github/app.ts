import { App } from "@octokit/app";
import { env } from "../env.js";

let appInstance: App | null = null;

/** Istanza singleton della GitHub App di JoJoX, usata per autenticarsi come una specifica installazione. */
export function getGithubApp(): App {
  if (!appInstance) {
    appInstance = new App({
      appId: env.githubAppId,
      privateKey: env.githubPrivateKey,
      webhooks: { secret: env.githubWebhookSecret },
    });
  }
  return appInstance;
}
