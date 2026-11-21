// Two bounded SELECTs under READ ONLY; existing editor SELECT privileges suffice.
import { COLLECTION_SOURCE_ID, type CollectionOperations, type CollectionRun } from "@aihot/contracts/collection-operations";
import { sql } from "../db.ts";
import { readWorkerObservation } from "./worker-observation.ts";
const timestamp = (value: unknown): string | null => {
  if (!(value instanceof Date) && typeof value !== "string") return null;
  const t = new Date(value).getTime();
  return Number.isFinite(t) ? new Date(t).toISOString() : null;
};
const count = (value: unknown): number | null => typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
export function projectCollectionRun(row: Record<string, unknown>, now: number): CollectionRun {
  const startedAt = timestamp(row.started_at), finishedAt = timestamp(row.finished_at);
  let outcome: CollectionRun["outcome"] = ["running", "ok", "failed", "skipped"].includes(String(row.status)) ? row.status as CollectionRun["outcome"] : "unknown";
  if (!startedAt || Date.parse(startedAt) > now + 5_000 || (finishedAt !== null && (Date.parse(finishedAt) > now + 5_000 || Date.parse(finishedAt) < Date.parse(startedAt!))) || (outcome === "running" && (finishedAt !== null || now - Date.parse(startedAt) > 30 * 60_000)) || (["ok", "failed", "skipped"].includes(outcome) && !finishedAt)) outcome = "unknown";
  const category = ["limit", "timeout", "tls", "network", "access", "source_format", "other"].includes(String(row.error_category)) ? row.error_category as CollectionRun["errorCategory"] : "other";
  return { startedAt, finishedAt, outcome, foundCount: count(row.found_count), newCount: count(row.new_count), errorCategory: outcome === "failed" ? category : null };
}
export async function readCollectionOperations(options: { database?: Pick<typeof sql, "begin">; observe?: typeof readWorkerObservation; now?: number } = {}): Promise<CollectionOperations> {
  const now = options.now ?? Date.now();
  const worker = await (options.observe ?? readWorkerObservation)(now);
  const result: CollectionOperations = { observedAt: new Date(now).toISOString(), sourceState: "unavailable", source: null, worker, runs: [] };
  try {
    const observed = await (options.database ?? sql).begin("READ ONLY", async (tx) => {
      await tx`SET LOCAL statement_timeout = '3000ms'`;
      const [source] = await tx`SELECT enabled, interval_minutes, next_fetch_at, last_fetch_at, last_ok_at FROM sources WHERE id = ${COLLECTION_SOURCE_ID}`;
      // Error text and detail never leave PostgreSQL, even for an authenticated reader.
      const runs = await tx`SELECT started_at, finished_at, status, found_count, new_count,
        CASE WHEN status <> 'failed' THEN NULL
          WHEN error ~* '(budget|quota|rate.limit|429)' THEN 'limit'
          WHEN error ~* '(timeout|timed out|abort)' THEN 'timeout'
          WHEN error ~* '(certificate|tls|ssl)' THEN 'tls'
          WHEN error ~* '(dns|ENOTFOUND|ECONN|network|socket)' THEN 'network'
          WHEN error ~* '(401|403|unauthor|forbidden)' THEN 'access'
          WHEN error ~* '(parse|xml|rss|invalid)' THEN 'source_format'
          ELSE 'other' END AS error_category
        FROM fetch_runs WHERE source_id = ${COLLECTION_SOURCE_ID} ORDER BY started_at DESC, id DESC LIMIT 20`;
      return { source, runs };
    });
    if (!observed.source) return { ...result, sourceState: "missing" };
    const s = observed.source;
    if (typeof s.enabled !== "boolean" || !Number.isInteger(s.interval_minutes) || s.interval_minutes < 1 || s.interval_minutes > 1440) return result;
    return { ...result, sourceState: "ok", source: { enabled: s.enabled, intervalMinutes: s.interval_minutes, nextFetchAt: timestamp(s.next_fetch_at), lastFetchAt: timestamp(s.last_fetch_at), lastOkAt: timestamp(s.last_ok_at) }, runs: observed.runs.map((r) => projectCollectionRun(r, now)) };
  } catch {
    // Database failures are states, never raw exception/DSN text in the response.
    return result;
  }
}
