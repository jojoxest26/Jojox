import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createIpRateLimit } from "../../src/server/util/rateLimit.js";

function fakeReq(ip: string) {
  return { ip } as import("express").Request;
}

function fakeRes() {
  const res: { statusCode?: number; body?: unknown; status: (code: number) => typeof res; json: (body: unknown) => typeof res } = {
    status(code: number) {
      res.statusCode = code;
      return res;
    },
    json(body: unknown) {
      res.body = body;
      return res;
    },
  };
  return res;
}

describe("createIpRateLimit", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("lascia passare le richieste entro il limite", () => {
    const limiter = createIpRateLimit({ windowMs: 60_000, max: 3, message: "troppe richieste" });
    const req = fakeReq("1.2.3.4");
    const next = vi.fn();

    limiter(req, fakeRes() as unknown as import("express").Response, next);
    limiter(req, fakeRes() as unknown as import("express").Response, next);
    limiter(req, fakeRes() as unknown as import("express").Response, next);

    expect(next).toHaveBeenCalledTimes(3);
  });

  it("blocca con 429 oltre il limite, con il messaggio dato", () => {
    const limiter = createIpRateLimit({ windowMs: 60_000, max: 2, message: "troppe richieste" });
    const req = fakeReq("1.2.3.4");
    const next = vi.fn();

    limiter(req, fakeRes() as unknown as import("express").Response, next);
    limiter(req, fakeRes() as unknown as import("express").Response, next);
    const res = fakeRes();
    limiter(req, res as unknown as import("express").Response, next);

    expect(next).toHaveBeenCalledTimes(2);
    expect(res.statusCode).toBe(429);
    expect(res.body).toEqual({ error: "troppe richieste" });
  });

  it("conta IP diversi in modo indipendente", () => {
    const limiter = createIpRateLimit({ windowMs: 60_000, max: 1, message: "troppe richieste" });
    const next = vi.fn();

    limiter(fakeReq("1.1.1.1"), fakeRes() as unknown as import("express").Response, next);
    limiter(fakeReq("2.2.2.2"), fakeRes() as unknown as import("express").Response, next);

    expect(next).toHaveBeenCalledTimes(2);
  });

  it("riapre il conteggio dopo la fine della finestra", () => {
    const limiter = createIpRateLimit({ windowMs: 60_000, max: 1, message: "troppe richieste" });
    const req = fakeReq("1.2.3.4");
    const next = vi.fn();

    limiter(req, fakeRes() as unknown as import("express").Response, next);
    const blocked = fakeRes();
    limiter(req, blocked as unknown as import("express").Response, next);
    expect(blocked.statusCode).toBe(429);

    vi.advanceTimersByTime(60_001);

    limiter(req, fakeRes() as unknown as import("express").Response, next);
    expect(next).toHaveBeenCalledTimes(2);
  });
});
