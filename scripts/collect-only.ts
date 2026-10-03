// Explicit opt-in; never starts worker, reads model credentials, or enables the ordinary collector.
import { readFileSync } from "node:fs";
import { closeDb, sql } from "@aihot/backend/db";
import { collectOnlyBatch } from "@aihot/backend/sources/collect-only";

const args = process.argv.slice(2);
if (args.length !== 1 || !["--seed-only", "--run"].includes(args[0]!)) {
  throw new Error("Usage: node scripts/collect-only.ts --seed-only | --run");
}
const { sources } = JSON.parse(readFileSync(new URL("../industry/collect-sources.json", import.meta.url), "utf8"));
try {
  if (args[0] === "--seed-only") {
    await sql.begin(async tx => {
      for (const source of sources) {
        await tx`INSERT INTO sources (id,name,kind,config,tier,enabled,participation_mode,site_fulltext,syndicate_fulltext,collect_only)
          VALUES (${source.id},${source.name},'rss',${tx.json(source.config)},'T2',false,'isolated',false,false,true)
          ON CONFLICT (id) DO NOTHING`;
        const [existing] = await tx`SELECT * FROM sources WHERE id=${source.id} FOR UPDATE`;
        if (!existing?.collect_only || existing.kind !== 'rss' || existing.enabled || existing.participation_mode !== 'isolated'
          || existing.site_fulltext || existing.syndicate_fulltext || JSON.stringify(existing.config) !== JSON.stringify(source.config)) {
          throw new Error(`Source ID conflict: ${source.id}; existing source was not modified`);
        }
      }
    });
    console.log("Collect-only candidates registered disabled/isolated; no HTTP requests made.");
  } else {
    console.log(JSON.stringify(await collectOnlyBatch(sources.map((s: { id: string }) => s.id), { queue: false, feedUrls: Object.fromEntries(sources.map((s: { id: string; config: { feedUrl: string } }) => [s.id, s.config.feedUrl])) }), null, 2));
  }
} finally {
  await closeDb();
}
