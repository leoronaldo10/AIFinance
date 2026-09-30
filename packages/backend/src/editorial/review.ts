import type { EditorialCopy, EditorialVersion } from "@aihot/contracts/editorial";
import { z } from "zod";
import { CATEGORY_KEYS } from "@aihot/contracts/taxonomy";
import { sql, type Tx } from "../db.ts";
import { sha256, stableJson } from "../lib/ids.ts";

export const FinanceSchema = z.object({
  relevance: z.string().trim().min(1).max(1500),
  scenarios: z.array(z.string().trim().min(1).max(40)).min(1).max(8),
  availability: z.enum(["available", "limited", "unknown"]),
  conditions: z.string().trim().min(1).max(1500),
  nextStep: z.string().trim().min(1).max(1500),
  limitations: z.string().trim().min(1).max(1500),
  evidence: z.enum(["announcement", "tested", "inference"]),
}).strict();

export const CopySchema = z.object({
  title: z.string().trim().min(1).max(300), summary: z.string().trim().min(1).max(4000),
  reason: z.string().max(1000), category: z.enum(CATEGORY_KEYS).nullable(),
  tags: z.array(z.string().trim().min(1).max(60)).max(20), selected: z.boolean(),
  score: z.number().min(0).max(100).nullable(), finance: FinanceSchema.nullable(),
}).strict();

/** Caller holds the article lock. Reprojection never replaces a manual draft with the same candidate. */
export async function reviewedCopy(tx: Tx, articleId: string, copy: EditorialCopy, evidence: EditorialVersion["evidence"]) {
  await tx`INSERT INTO editorial_review_state (article_id) VALUES (${articleId}) ON CONFLICT DO NOTHING`;
  const [state] = await tx<{ current_version: number; candidate_hash: string | null }[]>`
    SELECT current_version, candidate_hash FROM editorial_review_state WHERE article_id = ${articleId} FOR UPDATE`;
  const hash = sha256(stableJson({ copy, evidence }));
  if (state!.candidate_hash !== hash) {
    const version = state!.current_version + 1;
    await tx`INSERT INTO editorial_versions (article_id, version, copy, evidence, actor)
      VALUES (${articleId}, ${version}, ${tx.json(copy as never)}, ${tx.json(evidence as never)}, 'pipeline')`;
    await tx`UPDATE editorial_review_state SET current_version = ${version}, candidate_hash = ${hash} WHERE article_id = ${articleId}`;
  }
  const [published] = await tx<{ copy: EditorialCopy; version: number }[]>`
    SELECT v.copy, v.version FROM editorial_review_state s JOIN editorial_versions v
    ON v.article_id = s.article_id AND v.version = s.published_version
    WHERE s.article_id = ${articleId} AND NOT s.withdrawn AND v.status = 'approved'`;
  return published ?? null;
}

export async function reviewDetail(articleId: string) {
  const [state] = await sql`SELECT * FROM editorial_review_state WHERE article_id = ${articleId}`;
  if (!state) return null;
  const versions = await sql<EditorialVersion[]>`SELECT * FROM editorial_versions WHERE article_id = ${articleId} ORDER BY version DESC LIMIT 50`;
  return { articleId, currentVersion: state.current_version as number, publishedVersion: state.published_version as number | null, withdrawn: state.withdrawn as boolean, versions };
}
