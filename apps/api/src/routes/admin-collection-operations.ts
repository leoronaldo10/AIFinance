import type { FastifyInstance } from "fastify";
import { readCollectionOperations } from "@aihot/backend/admin/collection-operations";
import { adminHandler } from "./admin-auth.ts";
import { sendProblem } from "../http/respond.ts";
/** Only this fixed-source GET exists. Register under the existing private admin guard. */
export function registerCollectionOperations(app: FastifyInstance, read = readCollectionOperations) {
  app.get("/api/admin/collection-operations", adminHandler(async (req, reply) => {
    reply.header("X-Robots-Tag", "noindex, nofollow");
    if (Object.keys((req.query ?? {}) as object).length) return sendProblem(req, reply, { status: 400, code: "invalid_request", detail: "此页面不接受信源或路径参数。" });
    try {
      return await read();
    } catch {
      return sendProblem(req, reply, { status: 503, code: "temporarily_unavailable", detail: "采集状态暂不可用。" });
    }
  }));
}
