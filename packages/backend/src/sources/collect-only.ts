// Deliberately independent of collectors/jobs: RSS bytes → material revisions, with no processing.
import { config } from "../config.ts";
import { sql } from "../db.ts";
import { identityKeyFor, upsertMaterial } from "../content/materials.ts";
import { fetchRss } from "./rss.ts";
import type { SourceRow } from "./types.ts";

export const COLLECT_ONLY_BATCH_LIMIT = 3;

export async function collectOnlyBatch(sourceIds: string[], opts: { queue: false; feedUrls?: Record<string, string> }) {
  if (opts.queue !== false || config.modelCallsEnabled || process.env.COLLECT_ENABLED !== "false") {
    throw new Error("Collect-only requires queue:false, MODEL_CALLS_ENABLED=false and COLLECT_ENABLED=false");
  }
  if (config.allowPrivateNetworkFetch && process.env.NODE_ENV !== "test") throw new Error("Private network fetch is test-only for collect-only");
  if (!sourceIds.length || sourceIds.length > 3 || new Set(sourceIds).size !== sourceIds.length) {
    throw new Error("Choose 1–3 distinct RSS sources");
  }
  let activeSource: string | null = null;
  try {
    return await sql.begin(async tx => {
      // A timer/manual overlap must not advance the same cursor twice.
      const [lock] = await tx`SELECT pg_try_advisory_xact_lock(718643209) AS locked`;
      if (!lock!.locked) throw new Error("Collect-only batch already running");
      const sources = await tx<(SourceRow & { site_fulltext: boolean; syndicate_fulltext: boolean })[]>`SELECT * FROM sources WHERE id IN ${tx(sourceIds)} ORDER BY id FOR UPDATE`;
      if (sources.length !== sourceIds.length || sources.some(s => !s.collect_only || s.kind !== "rss" || s.enabled || s.participation_mode !== "isolated" || s.site_fulltext || s.syndicate_fulltext
        || Object.keys(s.config).some(k => k !== "feedUrl") || !s.config.feedUrl)) {
        throw new Error("Collect-only requires disabled, isolated RSS sources with only feedUrl configured");
      }
      if (opts.feedUrls && sources.some(s => opts.feedUrls![s.id] !== s.config.feedUrl)) {
        throw new Error("RSS URL differs from the fixed-source allowlist");
      }
      for (const source of sources) {
        const url = new URL(String(source.config.feedUrl));
        if (url.username || url.password) throw new Error("RSS URL credentials are forbidden");
      }
      const results: Array<{ sourceId: string; found: number; processed: number; created: number; revised: number; reason: string }> = [];
      let remaining = COLLECT_ONLY_BATCH_LIMIT;
      for (const [index, source] of sources.entries()) {
        activeSource = source.id;
        // Force reread: conditional 304 cannot hide entries beyond this batch's tiny window.
        const feed = await fetchRss(source, { force: true, publicTextOnly: true });
        const seen = new Set<string>();
        const candidates = feed.candidates.filter(c => {
          try {
            const url = new URL(c.url);
            if (!/^https?:$/.test(url.protocol) || url.username || url.password) return false;
          } catch { return false; }
          const key = identityKeyFor({ ...c, sourceId: source.id, via: "fetch" });
          if (seen.has(key)) return false;
          seen.add(key);
          return true;
        });
        const offset = Math.max(0, Number(source.cursor?.collectOnlyOffset) || 0) % (candidates.length || 1);
        const limit = Math.ceil(remaining / (sources.length - index));
        const batch = candidates.slice(offset, offset + limit);
        let created = 0;
        let revised = 0;
        for (const candidate of batch) {
          const result = await upsertMaterial({ ...candidate, sourceId: source.id, via: "fetch", collectOnly: true, media: [], bodyHtml: null }, tx);
          created += Number(result.created);
          revised += Number(result.revised);
        }
        remaining -= batch.length;
        const reason = !candidates.length ? "RSS 没有可用的 HTTP(S) 条目" : !created && !revised
          ? "本批未新增或修订；可能已收录，仅保留发现记录" : "已保存公开 RSS 原始候选；未进行 AI 筛选";
        const cursor = { ...(source.cursor ?? {}), collectOnlyOffset: (offset + batch.length) % (candidates.length || 1) };
        await tx`UPDATE sources SET cursor=${tx.json(cursor)}, last_fetch_at=now(), last_ok_at=now(),
          health='ok', fail_count=0, last_error=NULL, updated_at=now() WHERE id=${source.id}`;
        await tx`INSERT INTO fetch_runs (source_id, status, finished_at, found_count, new_count, detail)
          VALUES (${source.id}, 'ok', now(), ${candidates.length}, ${created}, ${tx.json({ collectOnly: true, processed: batch.length, revised, reason })})`;
        results.push({ sourceId: source.id, found: candidates.length, processed: batch.length, created, revised, reason });
      }
      return results;
    });
  } catch (error) {
    if (activeSource) {
      const message = String(error instanceof Error ? error.message : error).slice(0, 1000);
      await sql.begin(async tx => {
        await tx`UPDATE sources SET last_fetch_at=now(), fail_count=fail_count+1, health='degraded',
          last_error=${message}, updated_at=now() WHERE id=${activeSource!}`;
        await tx`INSERT INTO fetch_runs (source_id,status,finished_at,error,detail)
          VALUES (${activeSource!},'failed',now(),${message},${tx.json({ collectOnly: true, batchRolledBack: true })})`;
      });
    }
    throw error;
  }
}
