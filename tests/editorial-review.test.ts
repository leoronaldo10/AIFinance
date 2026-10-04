import { tag } from "./setup.ts";
import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { config } from "@aihot/backend/config";
import { sql, closeDb } from "@aihot/backend/db";
import { stopBoss } from "@aihot/backend/jobs/queue";
import { publishArticle } from "@aihot/backend/publication/publish";
import { importEditorial, editEditorial, reviewEditorial, reviewDetail, createEditorialExport, listEditorialExports, publishEditorialEdition, currentEditorialEdition } from "@aihot/backend/admin/editorial";
import { setVisibility } from "@aihot/backend/admin/content";
import { buildApp } from "../apps/api/src/app.ts";
import type { EditorialCopy } from "@aihot/contracts/editorial";

process.env.EDITORIAL_AUTOMATIC_FIXTURES = "false";
config.modelCallsEnabled = false;
const app = await buildApp();
const actor = "test-editor";
const notes = "已核对原文、适用范围和证据状态";
// Other engine suites share this database and intentionally leave delayed ledger entries.
// Release those fixtures so the global sync watermark can reach this suite's approvals.
before(async () => { await sql`UPDATE selected_ledger SET visible_at=now() WHERE visible_at>now()`; });
const copy: EditorialCopy = {
  title: "表格分析工具新增关联字段检查", summary: "工具公告新增字段检查，尚未证明能够独立完成财务对账。",
  reason: "适合关注数据核对的财务人员", category: "tip", tags: ["表格整理"], selected: true, score: 80,
  finance: { relevance: "整理多部门表格时，可关注字段一致性检查。", scenarios: ["表格整理", "对账"], availability: "unknown",
    conditions: "原文未说明国内版本和收费条件。", nextStep: "核实版本后，用公开样表检查字段。",
    limitations: "本条为公告解读，未进行独立实测。", evidence: "announcement" },
};
async function draft() {
  const t = tag();
  const { articleId } = await importEditorial({ title: `原文-${t}`, url: `https://example.com/${t}`, text: `SOURCE-ONLY-${t} 公开的原文材料用于编辑核查，未经审核不可出现在网站正文中。` }, actor);
  return articleId;
}
async function ready(id: string, overrides: Partial<EditorialCopy> = {}) {
  const state = await reviewDetail(id);
  return (await editEditorial(id, { version: state!.currentVersion, note: notes, copy: { ...copy, ...overrides } }, actor))!;
}
async function approve(id: string, version: number) { return reviewEditorial(id, 'approve', { version, note: notes }, actor); }
after(async () => { await app.close(); await stopBoss(); await closeDb(); });

test("drafts have no public detail, markdown, OG image, feed, search or sync entry", async () => {
  const id = await draft();
  for (const path of [`/api/site/items/${id}`, `/api/site/items/${id}/original`, `/items/${id}/markdown`, `/og/items/${id}.png`]) {
    const res = await app.inject({ method:'GET', url:path });
    assert.equal(res.statusCode,404,path);
  }
  for (const path of ['/api/site/timeline','/api/site/pool','/api/v1/items','/api/v1/selected/snapshot','/feed.xml','/feed/all.xml','/sitemap.xml']) {
    const res = await app.inject({ method:'GET', url:path });
    assert.equal(res.statusCode,200,path);
    assert.ok(!res.body.includes(id),path);
  }
  assert.equal((await sql`SELECT 1 FROM selected_ledger WHERE article_id=${id}`).length,0);
});

test("approval requires a complete financial explanation; approved copy appears without raw source text", async () => {
  const id = await draft();
  await assert.rejects(approve(id,1));
  const state = await ready(id);
  await approve(id,state.currentVersion);
  const res = await app.inject({ method:'GET',url:`/api/site/items/${id}` });
  assert.equal(res.statusCode,200);
  assert.equal(res.json().title,copy.title);
  assert.deepEqual(res.json().finance,copy.finance);
  assert.equal(res.json().body,null);
  assert.equal((await app.inject({url:`/items/${id}/markdown`})).statusCode,200);
  assert.ok(!res.body.includes('SOURCE-ONLY-'));
  const snap = await app.inject({method:'GET',url:'/api/v1/selected/snapshot'});
  assert.ok(snap.body.includes(id));
});

test("editing and pipeline regeneration preserve the approved version, and stale approvals fail", async () => {
  const id = await draft(); const initial = await ready(id); await approve(id,initial.currentVersion);
  const next = await ready(id,{title:'尚未审核的改写'});
  await assert.rejects(approve(id,initial.currentVersion),/更新/);
  assert.equal((await app.inject({url:`/api/site/items/${id}`})).json().title,copy.title);
  await publishArticle(id);
  assert.equal((await reviewDetail(id))!.currentVersion,next.currentVersion,'reprojection must not overwrite manual edits');
  await sql`INSERT INTO analyses (article_id,input_revision,origin,relevance,title_zh,summary_zh,selected,score)
    VALUES (${id},1,'rule','pass','新的模型输出','这是未审核的新摘要',true,95)`;
  await publishArticle(id);
  assert.ok((await reviewDetail(id))!.currentVersion > next.currentVersion);
  const publicCopy=(await app.inject({url:`/api/site/items/${id}`})).json();
  assert.equal(publicCopy.title,copy.title); assert.equal(publicCopy.summary,copy.summary);
});

test("only one concurrent editor can save against a version", async () => {
  const id=await draft();
  const results=await Promise.allSettled([ready(id,{title:'编辑甲'}),ready(id,{title:'编辑乙'})]);
  assert.equal(results.filter(r=>r.status==='fulfilled').length,1);
  assert.equal(results.filter(r=>r.status==='rejected').length,1);
});

test("rejected drafts need a new edit; withdrawal removes every article exit and cannot be undone by the old visibility control", async () => {
  const id=await draft(); const state=await ready(id);
  await reviewEditorial(id,'reject',{version:state.currentVersion,note:notes},actor);
  await assert.rejects(approve(id,state.currentVersion));
  const revised=await ready(id); await approve(id,revised.currentVersion);
  await reviewEditorial(id,'withdraw',{version:revised.currentVersion,note:notes},actor);
  await setVisibility(id,{visibility:'public',version:0,reason:notes},actor);
  for (const path of [`/api/site/items/${id}`,`/og/items/${id}.png`]) assert.equal((await app.inject({url:path})).statusCode,404);
  for (const path of ['/api/v1/items','/feed.xml','/api/v1/selected/snapshot']) assert.ok(!(await app.inject({url:path})).body.includes(id));
  const ledger=await sql`SELECT op FROM selected_ledger WHERE article_id=${id} ORDER BY seq DESC LIMIT 1`;
  assert.equal(ledger[0]!.op,'remove');
});

test("channel exports use immutable approved copies, escape HTML, and flag a changed or withdrawn source", async () => {
  const id=await draft(); const state=await ready(id,{title:'<img src=x onerror=alert(1)> 与表格分析'}); await approve(id,state.currentVersion);
  const e=await createEditorialExport({title:'财务周报',articles:[{id,version:state.currentVersion}]},actor);
  assert.ok(e.html.includes('&lt;img')); assert.ok(!e.html.includes('<img'));
  assert.ok(e.markdown.includes(copy.finance!.limitations));
  await ready(id,{title:'还未审核的版本'});
  const stillApproved=await createEditorialExport({title:'保留网站版本',articles:[{id,version:state.currentVersion}]},actor);
  assert.ok(!stillApproved.html.includes('还未审核的版本'));
  await reviewEditorial(id,'withdraw',{version:(await reviewDetail(id))!.currentVersion,note:notes},actor);
  await assert.rejects(createEditorialExport({title:'不可出稿',articles:[{id,version:state.currentVersion}]},actor));
  assert.equal((await listEditorialExports()).find(r=>r.id===e.id)!.needs_update,true);
});

test("compiled website editions disappear when a cited approved version is withdrawn", async () => {
  const id=await draft(); const state=await ready(id); await approve(id,state.currentVersion);
  const e=await createEditorialExport({title:'可核对的财务简报',articles:[{id,version:state.currentVersion}]},actor);
  const edition=await currentEditorialEdition();
  const published=await publishEditorialEdition(e.id,actor,edition);
  await assert.rejects(publishEditorialEdition(e.id,actor,edition),/更新/);
  await publishEditorialEdition(e.id,actor,await currentEditorialEdition());
  assert.ok(published);
  const key=published!.url.split('/').at(-1)!;
  assert.equal((await app.inject({url:`/api/v1/dailies/${key}`})).statusCode,200);
  await reviewEditorial(id,'withdraw',{version:state.currentVersion,note:notes},actor);
  assert.equal((await app.inject({url:`/api/v1/dailies/${key}`})).statusCode,404);
  await sql`DELETE FROM reports WHERE kind='daily' AND key=${key}`;
});

test("editorial HTTP routes require an admin and CSRF, and return useful validation errors", async () => {
  config.devAdmin=null;
  assert.equal((await app.inject({url:'/api/admin/editorial'})).statusCode,401);
  config.devAdmin={displayName:'Test Editor'};
  assert.equal((await app.inject({method:'POST',url:'/api/admin/editorial/import',payload:{}})).statusCode,403);
  const invalid=await app.inject({method:'POST',url:'/api/admin/editorial/import',headers:{'x-csrf-token':'dev'},payload:{title:'bad',url:'javascript:alert(1)',text:'x'.repeat(30)}});
  assert.equal(invalid.statusCode,400);
  config.devAdmin=null;
});
