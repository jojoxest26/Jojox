import { afterEach, describe, expect, it, vi } from "vitest";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.resetModules();
  vi.doUnmock("../../src/server/env.js");
});

describe("notifyEmail", () => {
  it("does nothing when RESEND_API_KEY is not set", async () => {
    vi.doMock("../../src/server/env.js", () => ({ env: { resendApiKey: null } }));
    const { notifyEmail } = await import("../../src/server/email/notify.js");

    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await notifyEmail("a@b.it", "oggetto", "<p>ciao</p>");

    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("does nothing when there is no recipient", async () => {
    vi.doMock("../../src/server/env.js", () => ({ env: { resendApiKey: "re_test" } }));
    const { notifyEmail } = await import("../../src/server/email/notify.js");

    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await notifyEmail(null, "oggetto", "<p>ciao</p>");
    await notifyEmail(undefined, "oggetto", "<p>ciao</p>");

    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("posts the email to the Resend API when configured", async () => {
    vi.doMock("../../src/server/env.js", () => ({ env: { resendApiKey: "re_test" } }));
    const { notifyEmail } = await import("../../src/server/email/notify.js");

    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200 });
    vi.stubGlobal("fetch", fetchMock);

    await notifyEmail("a@b.it", "oggetto", "<p>ciao</p>");

    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.resend.com/emails",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({
          Authorization: "Bearer re_test",
          "Content-Type": "application/json",
        }),
        body: JSON.stringify({ from: "JoJoX <avvisi@jojox.it>", to: "a@b.it", subject: "oggetto", html: "<p>ciao</p>" }),
      })
    );
  });

  it("does not throw when Resend responds with an error status", async () => {
    vi.doMock("../../src/server/env.js", () => ({ env: { resendApiKey: "re_test" } }));
    const { notifyEmail } = await import("../../src/server/email/notify.js");
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 422 }));

    await expect(notifyEmail("a@b.it", "oggetto", "<p>ciao</p>")).resolves.toBeUndefined();
  });

  it("does not throw when the network request itself fails", async () => {
    vi.doMock("../../src/server/env.js", () => ({ env: { resendApiKey: "re_test" } }));
    const { notifyEmail } = await import("../../src/server/email/notify.js");
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("network down")));

    await expect(notifyEmail("a@b.it", "oggetto", "<p>ciao</p>")).resolves.toBeUndefined();
  });
});

describe("buildAlertEmailHtml", () => {
  it("embeds the title, body and CTA into the HTML", async () => {
    const { buildAlertEmailHtml } = await import("../../src/server/email/notify.js");

    const html = buildAlertEmailHtml({
      title: "Titolo di prova",
      body: "Corpo di prova",
      ctaLabel: "Vai",
      ctaUrl: "https://jojox.it/test",
    });

    expect(html).toContain("Titolo di prova");
    expect(html).toContain("Corpo di prova");
    expect(html).toContain("https://jojox.it/test");
    expect(html).toContain("Vai");
    expect(html).toContain("JOJOX");
  });
});
