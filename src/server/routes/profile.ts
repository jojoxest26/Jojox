import { Router } from "express";
import { requireAuth, type AuthedRequest } from "../auth/middleware.js";
import { getPlanForUser } from "../plan.js";

export const profileRouter = Router();

profileRouter.get("/api/profile", requireAuth, async (req: AuthedRequest, res) => {
  const plan = await getPlanForUser(req.userId!);
  res.json({ plan });
});
