import type { EditorialCopy, EditorialVersion } from "@aihot/contracts/editorial";
import { AVAILABILITY_LABELS, EVIDENCE_LABELS } from "@aihot/contracts/editorial";
import { z } from "zod";
import { sql } from "../db.ts";
import { CopySchema, reviewDetail } from "../editorial/review.ts";
import { publishArticle, publishArticleTx } from "../publication/publish.ts";
import { upsertMaterial } from "../content/materials.ts";
import { Conflict } from "./sources.ts";
import { audit } from "./auth.ts";
import { beijingDate } from "@aihot/contracts/time";

export { reviewDetail };
const bad = (message: string) => Object.assign(new Error(message), { statusCode: 400 });
function parse<T>(schema: z.ZodType<T>, input: unknown): T {
  const result = schema.safeParse(input);
  if (!result.success) throw bad(result.error.issues.map(i => `${i.path.join('.')}: ${i.message}`).join('; '));
  return result.data;
}
const VersionSchema = z.object({ version: z.number().int().positive(), note: z.string().trim().min(1).max(1000) });

export async function editorialQueue(status = "draft", page = 1) {
  if (!["draft", "approved", "rejected", "withdrawn", "all", "published"].includes(status)) throw bad("未知审核状态");
  return sql`SELECT s.article_id AS id, s.current_version, s.published_version, s.withdrawn,
    v.status, v.copy->>'title' AS title, pv.copy->>'title' AS published_title, v.created_at, a.url
    FROM editorial_review_state s JOIN editorial_versions v ON v.article_id=s.article_id AND v.version=s.current_version
    LEFT JOIN editorial_versions pv ON pv.article_id=s.article_id AND pv.version=s.published_version
    JOIN articles a ON a.id=s.article_id
    WHERE (${status}='all' OR (${status}='published' AND s.published_version IS NOT NULL AND NOT s.withdrawn) OR (${status}='withdrawn' AND s.withdrawn) OR (${status} <> 'withdrawn' AND v.status=${status} AND NOT s.withdrawn))
    ORDER BY v.created_at DESC, s.article_id LIMIT 30 OFFSET ${(Math.max(1, page) - 1) * 30}`;
}

/** Import is local material ingestion, never an HTTP fetch or model call. */
export async function importEditorial(input: unknown, actor: string) {
  const b = parse(z.object({ title: z.string().trim().min(1).max(300), url: z.url().max(2000), text: z.string().trim().min(20).max(60000) }).strict(), input);
  if (!/^https?:\/\//i.test(b.url) || new URL(b.url).username || new URL(b.url).password) throw bad("请填写不含凭据的 HTTP(S) 原文链接");
  await sql`INSERT INTO sources (id, name, kind, tier, participation_mode, enabled, site_fulltext, syndicate_fulltext)
    VALUES ('finance-editorial', '编辑选题（原文见链接）', 'external', 'T2', 'editorial', false, false, false) ON CONFLICT DO NOTHING`;
  const material = await upsertMaterial({ sourceId: 'finance-editorial', url: b.url, title: b.title, bodyText: b.text, bodyStatus: 'ok', via: 'ingest' });
  await publishArticle(material.articleId);
  await audit(actor, 'editorial.import', material.articleId, null, null, { url: b.url });
  return { articleId: material.articleId };
}

/** Every edit creates a version; optimistic concurrency prevents a stale browser from approving new text. */
export async function editEditorial(articleId: string, input: unknown, actor: string) {
  const b = parse(VersionSchema.extend({ copy: CopySchema }).strict(), input);
  await sql.begin(async tx => {
    await tx`SELECT id FROM articles WHERE id=${articleId} FOR UPDATE`;
    const [state] = await tx<{ current_version: number }[]>`SELECT current_version FROM editorial_review_state WHERE article_id=${articleId} FOR UPDATE`;
    if (!state || state.current_version !== b.version) throw new Conflict("稿件已有更新，请刷新后编辑");
    const [old] = await tx<EditorialVersion[]>`SELECT * FROM editorial_versions WHERE article_id=${articleId} AND version=${b.version}`;
    const version = b.version + 1;
    await tx`INSERT INTO editorial_versions (article_id, version, copy, evidence, actor, note)
      VALUES (${articleId}, ${version}, ${tx.json(b.copy as never)}, ${tx.json(old!.evidence as never)}, ${actor}, ${b.note})`;
    await tx`UPDATE editorial_review_state SET current_version=${version} WHERE article_id=${articleId}`;
    await tx`INSERT INTO audit_log (actor, action, subject, reason, after)
      VALUES (${actor}, 'editorial.edit', ${articleId}, ${b.note}, ${tx.json({ version })})`;
  });
  return reviewDetail(articleId);
}

export async function reviewEditorial(articleId: string, action: string, input: unknown, actor: string) {
  if (!["approve", "reject", "withdraw"].includes(action)) throw bad("未知审核操作");
  const b = parse(VersionSchema.strict(), input);
  await sql.begin(async tx => {
    await tx`SELECT id FROM articles WHERE id=${articleId} FOR UPDATE`;
    const [state] = await tx<{ current_version: number }[]>`SELECT current_version FROM editorial_review_state WHERE article_id=${articleId} FOR UPDATE`;
    if (!state || state.current_version !== b.version) throw new Conflict("稿件已有更新，请刷新后审核");
    const [v] = await tx<EditorialVersion[]>`SELECT * FROM editorial_versions WHERE article_id=${articleId} AND version=${b.version}`;
    if (action === "approve") {
      const copy = parse(CopySchema, v!.copy);
      if (!copy.finance || !copy.category) throw bad("请补全财务解读、栏目和使用条件，再审核发布");
      if (v!.status === 'rejected') throw new Conflict("已拒绝版本不能直接发布，请先修改并保存新版本");
      await tx`UPDATE editorial_versions SET status='approved' WHERE article_id=${articleId} AND version=${b.version}`;
      await tx`UPDATE editorial_review_state SET published_version=${b.version}, withdrawn=false WHERE article_id=${articleId}`;
    } else if (action === 'reject') {
      if (v!.status !== 'draft') throw new Conflict("只能退回待审核稿件；已发布内容请撤回");
      await tx`UPDATE editorial_versions SET status='rejected' WHERE article_id=${articleId} AND version=${b.version}`;
    } else {
      await tx`UPDATE editorial_review_state SET withdrawn=true WHERE article_id=${articleId}`;
    }
    await publishArticleTx(tx, articleId);
    await tx`INSERT INTO audit_log (actor, action, subject, reason, after)
      VALUES (${actor}, ${'editorial.'+action}, ${articleId}, ${b.note}, ${tx.json({ version: b.version })})`;
  });
  return reviewDetail(articleId);
}

const escape = (s: string) => s.replace(/[&<>"']/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c]!));

export function channelCopy(title: string, entries: Array<{ copy: EditorialCopy; url: string }>) {
  const lines = [`# ${title}`, ""];
  const html = [`<section style="font-size:16px;line-height:1.8;color:#24333c"><h1>${escape(title)}</h1>`];
  for (const { copy, url } of entries) {
    const f = copy.finance!;
    const parts = [
      ["发生了什么", copy.summary], ["财务为什么关注", f.relevance],
      ["适用场景", f.scenarios.join("、")], ["现在能不能用", `${AVAILABILITY_LABELS[f.availability]}。${f.conditions}`],
      ["可以怎样尝试", f.nextStep], ["限制与依据", `${EVIDENCE_LABELS[f.evidence]}。${f.limitations}`],
    ];
    lines.push(`## ${copy.title}`, ""); html.push(`<h2>${escape(copy.title)}</h2>`);
    for (const [label, text] of parts) {
      lines.push(`### ${label}`, "", text!, "");
      html.push(`<h3>${escape(label!)}</h3><p>${escape(text!).replace(/\n/g, '<br>')}</p>`);
    }
    lines.push(`原文：${url}`, ""); html.push(`<p>原文：<a href="${escape(url)}">${escape(url)}</a></p>`);
  }
  html.push('</section>');
  return { markdown: lines.join('\n'), html: html.join('\n') };
}

export async function createEditorialExport(input: unknown, actor: string) {
  const b = parse(z.object({ title: z.string().trim().min(1).max(200), articles: z.array(z.object({ id: z.string().min(1).max(80), version: z.number().int().positive() }).strict()).min(1).max(10) }).strict(), input);
  if (new Set(b.articles.map(a => a.id)).size !== b.articles.length) throw bad("同一条资讯只能选择一次");
  return sql.begin(async tx => {
    // Same order as publication/review; hold article locks until the channel snapshot is committed.
    const ids = b.articles.map(a => a.id).sort();
    await tx`SELECT id FROM articles WHERE id IN ${tx(ids)} ORDER BY id FOR UPDATE`;
    const entries: Array<{ copy: EditorialCopy; url: string }> = [];
    for (const a of b.articles) {
      const [row] = await tx<{ copy: EditorialCopy; evidence: EditorialVersion['evidence'] }[]>`
        SELECT v.copy, v.evidence FROM editorial_versions v JOIN editorial_review_state s ON s.article_id=v.article_id
        JOIN publications p ON p.article_id=v.article_id
        WHERE v.article_id=${a.id} AND v.version=${a.version} AND s.published_version=v.version
        AND NOT s.withdrawn AND v.status='approved' AND p.visibility='public' AND p.review_version=v.version`;
      if (!row) throw new Conflict("选中的稿件尚未发布、已经更新或已撤回，请重新选稿");
      entries.push({ copy: row.copy, url: row.evidence.url });
    }
    const output = channelCopy(b.title, entries);
    const [saved] = await tx`INSERT INTO editorial_exports (title, article_versions, html, markdown, actor)
      VALUES (${b.title}, ${tx.json(b.articles)}, ${output.html}, ${output.markdown}, ${actor}) RETURNING id`;
    return { id: saved!.id as number, ...output };
  });
}

export async function listEditorialExports() {
  return sql`SELECT e.id, e.title, e.created_at, e.published_url, e.published_at,
    EXISTS (SELECT 1 FROM jsonb_array_elements(e.article_versions) x
      LEFT JOIN editorial_review_state s ON s.article_id=x->>'id'
      LEFT JOIN publications p ON p.article_id=s.article_id
      WHERE s.article_id IS NULL OR s.withdrawn OR s.published_version IS DISTINCT FROM (x->>'version')::integer OR p.visibility IS DISTINCT FROM 'public') AS needs_update
    FROM editorial_exports e ORDER BY e.id DESC LIMIT 30`;
}

export async function recordEditorialPublication(id: number, input: unknown, actor: string) {
  const b = parse(z.object({ url: z.url().max(2000) }).strict(), input);
  const url = new URL(b.url);
  if (url.protocol !== 'https:' || url.hostname !== 'mp.weixin.qq.com' || url.username || url.password) throw bad("请填写公众号文章的 HTTPS 链接");
  const [row] = await sql`UPDATE editorial_exports SET published_url=${b.url}, published_at=now() WHERE id=${id} RETURNING id`;
  if (!row) return null;
  await audit(actor, 'editorial.wechat-published', String(id), null, null, { url: b.url });
  return row;
}

/** Publish the exact selected copies as a website daily; no new model-written lead bypasses review. */
export async function currentEditorialEdition() {
  const key = beijingDate(Date.now());
  const [row] = await sql`SELECT revision FROM reports WHERE kind='daily' AND key=${key}`;
  return { key, revision: Number(row?.revision ?? 0) };
}

export async function publishEditorialEdition(id: number, actor: string, input: unknown) {
  const expected = parse(z.object({ key: z.string(), revision: z.number().int().nonnegative() }).strict(), input);
  return sql.begin(async tx => {
    const key = beijingDate(Date.now());
    if (expected.key !== key) throw new Conflict("日期已变化，请刷新后核对本期简报");
    await tx`SELECT pg_advisory_xact_lock(hashtext(${'editorial-daily:'+key}))`;
    const [previous] = await tx`SELECT * FROM reports WHERE kind='daily' AND key=${key} FOR UPDATE`;
    if (Number(previous?.revision ?? 0) !== expected.revision) throw new Conflict("本期简报已有更新，请刷新后核对");
    const [edition] = await tx<{ title: string; article_versions: Array<{ id: string; version: number }> }[]>`
      SELECT title, article_versions FROM editorial_exports WHERE id=${id}`;
    if (!edition) return null;
    const ids = edition.article_versions.map(a => a.id).sort();
    await tx`SELECT id FROM articles WHERE id IN ${tx(ids)} ORDER BY id FOR UPDATE`;
    const items = [];
    for (const ref of edition.article_versions) {
      const [row] = await tx<{ copy: EditorialCopy; url: string; source: string }[]>`
        SELECT v.copy, p.url, s.name AS source FROM publications p
        JOIN editorial_versions v ON v.article_id=p.article_id AND v.version=p.review_version
        JOIN sources s ON s.id=p.source_id
        WHERE p.article_id=${ref.id} AND p.review_version=${ref.version} AND p.visibility='public'`;
      if (!row) throw new Conflict("稿件版本已变化或撤回，请重新出稿");
      items.push({ itemId: ref.id, title: row.copy.title, summary: row.copy.summary, sourceName: row.source, sourceUrl: row.url });
    }
    const content = { editorialReviewed: true, articleVersions: edition.article_versions, exportId: id,
      lead: { title: edition.title, leadParagraph: '本期选编自编辑已审核的财务 AI 资讯。打开单条资讯可查看使用条件、限制与原文。' },
      sections: [{ title: '财务 AI 精选', items }], highlights: items.slice(0,3).map(i => i.itemId), flashes: [] };
    if (previous) {
      await tx`INSERT INTO report_revisions (report_id,revision,content,generated_at,reason)
        VALUES (${previous.id},${previous.revision},${tx.json(previous.content)},${previous.generated_at},'编辑重新核对后替换本期选稿') ON CONFLICT DO NOTHING`;
      await tx`UPDATE reports SET content=${tx.json(content)}, revision=revision+1, generated_at=now(), updated_at=now(), origin='manual', model=NULL WHERE id=${previous.id}`;
    } else {
      await tx`INSERT INTO reports (kind, key, window_start, window_end, content, generated_at, origin)
      VALUES ('daily', ${key}, now(), now(), ${tx.json(content)}, now(), 'manual')
      RETURNING id`;
    }
    await tx`INSERT INTO audit_log (actor, action, subject, after) VALUES (${actor}, 'editorial.edition', ${String(id)}, ${tx.json({ key })})`;
    return { url: `/daily/${key}` };
  });
}
