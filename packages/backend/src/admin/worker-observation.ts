// Reads a passive observer's allowlisted data. Never executes systemctl or a shell.
import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { COLLECTION_STALE_MS, COLLECTION_WORKER_UNIT, type WorkerObservation } from "@aihot/contracts/collection-operations";
const KEYS = ["format", "unit", "observedAt", "activeState", "loadState", "unitFileState"];
const unknown = (state: WorkerObservation["state"]): WorkerObservation => ({ state, observedAt: null, activeState: "unknown", loadState: "unknown", unitFileState: "unknown" });
export function parseWorkerObservation(value: unknown, now = Date.now()): WorkerObservation {
  if (!value || typeof value !== "object" || Array.isArray(value)) return unknown("invalid");
  const v = value as Record<string, unknown>;
  if (Object.keys(v).length !== KEYS.length || Object.keys(v).some((k) => !KEYS.includes(k)) || v.format !== 1 || v.unit !== COLLECTION_WORKER_UNIT || typeof v.observedAt !== "string") return unknown("invalid");
  const at = Date.parse(v.observedAt);
  if (!Number.isFinite(at) || at > now + 5_000 ||
    !["active", "inactive", "failed", "activating", "deactivating", "reloading", "unknown"].includes(String(v.activeState)) ||
    !["loaded", "not-found", "masked", "error", "unknown"].includes(String(v.loadState)) ||
    !["enabled", "disabled", "static", "masked", "unknown"].includes(String(v.unitFileState))) return unknown("invalid");
  return { state: now - at > COLLECTION_STALE_MS ? "stale" : "fresh", observedAt: new Date(at).toISOString(), activeState: v.activeState as WorkerObservation["activeState"], loadState: v.loadState as WorkerObservation["loadState"], unitFileState: v.unitFileState as WorkerObservation["unitFileState"] };
}
export async function readWorkerObservation(now = Date.now(), file = process.env.AIHOT_WORKER_STATUS_FILE): Promise<WorkerObservation> {
  if (!file) return unknown("missing");
  let handle;
  try {
    handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const s = await handle.stat();
    if (!s.isFile() || s.size > 4096 || s.mode & 0o022 || ![0, process.getuid?.()].includes(s.uid)) return unknown("invalid");
    const buffer = Buffer.alloc(4097);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    const after = await handle.stat();
    if (bytesRead > 4096 || s.size !== bytesRead || s.size !== after.size || s.mtimeMs !== after.mtimeMs) return unknown("invalid");
    return parseWorkerObservation(JSON.parse(buffer.subarray(0, bytesRead).toString("utf8")), now);
  } catch (e) {
    return unknown((e as NodeJS.ErrnoException).code === "ENOENT" ? "missing" : e instanceof SyntaxError ? "invalid" : "unavailable");
  } finally {
    await handle?.close().catch(() => {});
  }
}
