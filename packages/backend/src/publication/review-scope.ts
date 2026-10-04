import { config } from "../config.ts";
import { sql } from "../db.ts";

/** A compiled edition is public only while every cited approved version is still public. */
export function reviewedReportCondition() {
  if (!config.editorialReviewRequired) return sql`true`;
  return sql`content->>'editorialReviewed' = 'true'
    AND jsonb_array_length(coalesce(content->'articleVersions', '[]'::jsonb)) > 0
    AND NOT EXISTS (
      SELECT 1 FROM jsonb_array_elements(content->'articleVersions') x
      LEFT JOIN publications rp ON rp.article_id=x->>'id'
      WHERE rp.article_id IS NULL OR rp.visibility <> 'public' OR rp.review_version IS DISTINCT FROM (x->>'version')::integer
    )`;
}
