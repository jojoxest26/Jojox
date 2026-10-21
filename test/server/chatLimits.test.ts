import { describe, expect, it } from "vitest";
import { DAILY_CHAT_MESSAGE_LIMIT, DAILY_GENERAL_CHAT_LIMIT, type Plan } from "../../src/server/plan.js";

describe("chat limits", () => {
  it("keeps the expensive general-mode limit below the overall chat limit", () => {
    for (const plan of ["free", "pro", "team"] as Plan[]) {
      expect(DAILY_GENERAL_CHAT_LIMIT[plan]).toBeLessThanOrEqual(DAILY_CHAT_MESSAGE_LIMIT[plan]);
    }
    expect(DAILY_GENERAL_CHAT_LIMIT.free).toBe(0);
  });
});
