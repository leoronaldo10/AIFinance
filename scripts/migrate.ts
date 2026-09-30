// Applies database/migrations/*.sql in order, each in its own transaction. Safe to re-run.
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { REPO_ROOT } from "@aihot/backend/config";
import { closeDb, sql } from "@aihot/backend/db";

const dir = path.join(REPO_ROOT, "database/migrations");

await sql`CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`;
const applied = new Set((await sql<{ name: string }[]>`SELECT name FROM schema_migrations`).map((r) => r.name));

let count = 0;
for (const file of readdirSync(dir).filter((f) => f.endsWith(".sql")).sort()) {
  if (applied.has(file)) continue;
  const text = readFileSync(path.join(dir, file), "utf8");
  await sql.begin(async (tx) => {
    await tx.unsafe(text);
    await tx`INSERT INTO schema_migrations (name) VALUES (${file})`;
  });
  console.log(`applied ${file}`);
  count += 1;
}
console.log(count === 0 ? "database is up to date" : `${count} migration(s) applied`);
// Backfill the review queue after upgrading an existing site; projection never calls a model.
const { config } = await import("@aihot/backend/config");
if (config.editorialReviewRequired) {
  const { publishArticle } = await import("@aihot/backend/publication/publish");
  const pending = await sql<{ id: string }[]>`SELECT id FROM articles a WHERE NOT EXISTS (SELECT 1 FROM editorial_review_state s WHERE s.article_id=a.id)`;
  for (const a of pending) await publishArticle(a.id);
  if (pending.length) console.log(`${pending.length} article(s) prepared for editorial review`);
}
await closeDb();
