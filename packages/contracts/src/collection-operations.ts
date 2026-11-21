/** Private fixed-source monitoring contract. No source configuration or raw errors. */
export const COLLECTION_SOURCE_ID = "collect-dynamics-finance";
export const COLLECTION_WORKER_UNIT = "aifinance-native-resident.service";
export const COLLECTION_STALE_MS = 90_000;
export type ObservationState = "fresh" | "stale" | "missing" | "invalid" | "unavailable";
export type ServiceState = "active" | "inactive" | "failed" | "activating" | "deactivating" | "reloading" | "unknown";
export type FetchOutcome = "running" | "ok" | "failed" | "skipped" | "unknown";
export type FetchErrorCategory = "limit" | "timeout" | "tls" | "network" | "access" | "source_format" | "other";
export interface WorkerObservation {
  state: ObservationState;
  observedAt: string | null;
  activeState: ServiceState;
  loadState: "loaded" | "not-found" | "masked" | "error" | "unknown";
  unitFileState: "enabled" | "disabled" | "static" | "masked" | "unknown";
}
export interface CollectionRun {
  startedAt: string | null;
  finishedAt: string | null;
  outcome: FetchOutcome;
  foundCount: number | null;
  newCount: number | null;
  errorCategory: FetchErrorCategory | null;
}
export interface CollectionOperations {
  observedAt: string;
  sourceState: "ok" | "missing" | "unavailable";
  source: null | {
    enabled: boolean;
    intervalMinutes: number;
    nextFetchAt: string | null;
    lastFetchAt: string | null;
    lastOkAt: string | null;
  };
  worker: WorkerObservation;
  runs: CollectionRun[];
}
export type Eligibility = "paused" | "unknown" | "worker_unavailable" | "eligible" | "waiting";
/** Eligibility is not a promise that a fetch or paid analysis will run at this time. */
export function collectionEligibility(data: CollectionOperations, now = Date.now()): { state: Eligibility; at: string | null } {
  if (data.sourceState !== "ok" || !data.source) return { state: "unknown", at: null };
  const age = now - Date.parse(data.observedAt);
  if (!Number.isFinite(age) || age < -5_000 || age > COLLECTION_STALE_MS) return { state: "unknown", at: null };
  if (!data.source.enabled) return { state: "paused", at: null };
  if (data.worker.state !== "fresh") return { state: "unknown", at: null };
  const workerAge = now - Date.parse(data.worker.observedAt ?? "");
  if (!Number.isFinite(workerAge) || workerAge < -5_000 || workerAge > COLLECTION_STALE_MS) return { state: "unknown", at: null };
  if (data.worker.activeState === "unknown" || data.worker.loadState === "unknown") return { state: "unknown", at: null };
  if (data.worker.activeState !== "active" || data.worker.loadState !== "loaded") return { state: "worker_unavailable", at: null };
  if (data.source.nextFetchAt === null) return { state: "eligible", at: null };
  const due = Date.parse(data.source.nextFetchAt);
  if (!Number.isFinite(due)) return { state: "unknown", at: null };
  return { state: due <= now ? "eligible" : "waiting", at: data.source.nextFetchAt };
}
