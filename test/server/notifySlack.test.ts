import { afterEach, describe, expect, it, vi } from "vitest";
import { notifySlack } from "../../src/server/slack/notify.js";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("notifySlack", () => {
  it("does nothing when there is no webhook URL", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await notifySlack(null, "test");
    await notifySlack(undefined, "test");

    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("posts the message as JSON to the webhook URL", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200 });
    vi.stubGlobal("fetch", fetchMock);

    await notifySlack("https://hooks.slack.com/services/T000/B000/xxx", "ciao");

    expect(fetchMock).toHaveBeenCalledWith(
      "https://hooks.slack.com/services/T000/B000/xxx",
      expect.objectContaining({
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: "ciao" }),
      })
    );
  });

  it("does not throw when Slack responds with an error status", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 404 }));
    await expect(notifySlack("https://hooks.slack.com/services/T000/B000/xxx", "ciao")).resolves.toBeUndefined();
  });

  it("does not throw when the network request itself fails", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("network down")));
    await expect(notifySlack("https://hooks.slack.com/services/T000/B000/xxx", "ciao")).resolves.toBeUndefined();
  });
});