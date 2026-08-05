import { createHmac, timingSafeEqual } from "node:crypto";

/** Verifica la firma HMAC-SHA256 che GitHub allega a ogni webhook (X-Hub-Signature-256). */
export function verifyGithubSignature(
  payload: string,
  signatureHeader: string | undefined,
  secret: string
): boolean {
  if (!signatureHeader) return false;

  const expected = "sha256=" + createHmac("sha256", secret).update(payload).digest("hex");
  const expectedBuffer = Buffer.from(expected);
  const actualBuffer = Buffer.from(signatureHeader);

  if (expectedBuffer.length !== actualBuffer.length) return false;
  return timingSafeEqual(expectedBuffer, actualBuffer);
}
