import { useState } from "react";
import { Form, Link, useNavigate } from "react-router";
import type { Route } from "./+types/editorial";
import { adminGet } from "../../lib/admin.server";
import { useAdminAction } from "../../features/admin/action";
import { AdminPage, Button, Card, Input } from "../../features/admin/ui";

export interface QueueRow { id: string; title: string; published_title: string | null; status: string; current_version: number; published_version: number | null; withdrawn: boolean; created_at: string }
export async function loader({ request }: Route.LoaderArgs) {
  const sp = new URL(request.url).searchParams;
  const status = sp.get("status") ?? "draft";
  const page = Math.max(1, Number(sp.get("page")) || 1);
  const { rows } = await adminGet<{ rows: QueueRow[] }>(request, `/api/admin/editorial?${new URLSearchParams({ status, page: String(page) })}`);
  return { rows, status, page };
}
const labels: Record<string, string> = { draft: "待审核", approved: "已审核", rejected: "已退回", withdrawn: "已撤回", all: "全部" };
export default function Editorial({ loaderData: { rows, status, page } }: Route.ComponentProps) {
  const action = useAdminAction();
  const navigate = useNavigate();
  const [title, setTitle] = useState(""); const [url, setUrl] = useState(""); const [text, setText] = useState("");
  return <AdminPage title="财务资讯编辑台" subtitle="核对原文、写清财务关联，再审核发布。新稿件和重新生成的稿件都先在这里等待审核。">
    <div className="mb-5 flex flex-wrap gap-3">{Object.entries(labels).map(([key, label]) => <Link className={`chip ${status === key ? "bg-accent-soft text-accent" : ""}`} key={key} to={`?status=${key}`}>{label}</Link>)}<Link className="chip" to="/admin/editorial-exports">公众号出稿与发布记录 →</Link></div>
    <details className="mb-6 rounded-control border border-line bg-surface p-4"><summary className="cursor-pointer font-medium">添加公开资讯选题</summary>
      <form className="mt-4 grid gap-3" onSubmit={async e => { e.preventDefault(); const r = await action.run<{ articleId: string }>("POST", "/api/admin/editorial/import", { title, url, text }); if(r) navigate(`/admin/editorial/${r.articleId}`); }}>
        <label>原标题<Input required maxLength={300} value={title} onChange={e => setTitle(e.target.value)} /></label>
        <label>原文链接<Input required type="url" value={url} onChange={e => setUrl(e.target.value)} /></label>
        <label>供核对的原文内容<textarea required minLength={20} maxLength={60000} className="mt-1 min-h-40 w-full rounded-control border border-line bg-bg p-3" value={text} onChange={e => setText(e.target.value)} /></label>
        <p className="text-sm text-ink-3">只保存供审核的材料，不会自动抓取链接、调用模型或发布。请使用公开资料。</p>
        <Button type="submit" tone="primary" disabled={action.busy}>保存选题</Button>
      </form>
    </details>
    <Card title={`${labels[status] ?? status}资讯`}>
      {!rows.length && <p className="py-8 text-ink-3">暂无稿件。可以添加选题，或在信源配置完成后接收采集结果。</p>}
      <ul className="divide-y divide-line">{rows.map(r => <li key={r.id} className="py-4"><Link to={`/admin/editorial/${r.id}`} className="font-medium text-ink hover:text-accent">{r.title}</Link><p className="mt-1 text-sm text-ink-3">{r.withdrawn ? "已撤回" : labels[r.status]} · 当前第 {r.current_version} 版{r.published_version && !r.withdrawn ? ` · 网站保留第 ${r.published_version} 版` : ""}</p></li>)}</ul>
    </Card>
    <Form method="get" className="mt-4 flex gap-4"><input type="hidden" name="status" value={status} /><Button name="page" value={Math.max(1, page-1)} disabled={page === 1}>上一页</Button><span>第 {page} 页</span><Button name="page" value={page+1} disabled={rows.length < 30}>下一页</Button></Form>
  </AdminPage>;
}
