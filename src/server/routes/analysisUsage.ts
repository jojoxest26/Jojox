import { Router } from "express";
import { requireAuth, type AuthedRequest } from "../auth/middleware.js";
import { getAnalysisUsage } from "../analysisQuota.js";

export const analysisUsageRouter = Router();

analysisUsageRouter.get("/api/analysis-usage", requireAuth, async (req: AuthedRequest, res) => {
  const usage = await getAnalysisUsage(req.userId!);
  res.json(usage);
});
