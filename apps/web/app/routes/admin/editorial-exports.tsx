import { useState } from "react";
import { Link, useNavigate } from "react-router";
import type { Route } from "./+types/editorial-exports";
import type { QueueRow } from "./editorial";
import { adminGet } from "../../lib/admin.server";
import { useAdminAction } from "../../features/admin/action";
import { AdminPage, Button, Card, Input } from "../../features/admin/ui";

interface ExportRow { id: number; title: string; needs_update: boolean; published_url: string | null }
interface ExportDetail { id: number; title: string; markdown: string; html: string; edition: { key: string; revision: number } }
export async function loader({ request }: Route.LoaderArgs) {
  const id = new URL(request.url).searchParams.get('id');
  const [queue, exports, selected] = await Promise.all([
    adminGet<{ rows: QueueRow[] }>(request, '/api/admin/editorial?status=published'),
    adminGet<{ rows: ExportRow[] }>(request, '/api/admin/editorial/exports'),
    id ? adminGet<ExportDetail>(request, `/api/admin/editorial/exports/${encodeURIComponent(id)}`) : null,
  ]);
  return { articles: queue.rows.filter(r => r.published_version && !r.withdrawn), exports: exports.rows, selected };
}

export default function Exports({ loaderData: { articles, exports, selected } }: Route.ComponentProps) {
  const action = useAdminAction(); const navigate = useNavigate();
  const [ids, setIds] = useState<string[]>([]); const [title, setTitle] = useState('本周财务 AI 精选');
  const [publishedUrl, setPublishedUrl] = useState(''); const [feedback, setFeedback] = useState('');
  const selectedStatus = exports.find(e => e.id === selected?.id);
  async function copyHtml() {
    try {
      if (!selected) return;
      if (typeof ClipboardItem !== 'undefined' && navigator.clipboard?.write) {
        await navigator.clipboard.write([new ClipboardItem({ 'text/html': new Blob([selected.html], {type:'text/html'}), 'text/plain': new Blob([selected.markdown], {type:'text/plain'}) })]);
      } else { await navigator.clipboard.writeText(selected.markdown); }
      setFeedback('已复制，请粘贴到公众号编辑器并检查排版。');
    } catch { setFeedback('当前浏览器不支持复制，请使用下方下载或手动复制文稿。'); }
  }
  function download(ext: 'html' | 'md') {
    if (!selected) return;
    const url = URL.createObjectURL(new Blob([ext === 'html' ? selected.html : selected.markdown], {type: ext === 'html' ? 'text/html;charset=utf-8' : 'text/markdown;charset=utf-8'}));
    const a = document.createElement('a'); a.href=url; a.download=`finance-brief-${selected.id}.${ext}`; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  return <AdminPage title="公众号出稿与发布记录" subtitle="选择已审核的网站版本，生成排版稿。复制或导出后由你在公众号发布，再记录文章链接。">
    <Link to="/admin/editorial" className="mb-5 block">← 编辑台</Link>
    <div className="grid gap-6 xl:grid-cols-2">
      <div className="space-y-5"><Card title="选稿">
        <form className="space-y-4" onSubmit={async e => { e.preventDefault(); const result = await action.run<{id:number}>('POST', '/api/admin/editorial/exports', { title, articles: ids.map(id => ({ id, version: articles.find(a => a.id === id)!.published_version })) }); if(result) navigate(`?id=${result.id}`); }}>
          <label>本期标题<Input required maxLength={200} value={title} onChange={e => setTitle(e.target.value)} /></label>
          {!articles.length && <p className="text-ink-3">先在编辑台审核发布资讯，再来选稿。</p>}
          {articles.map(a => <label key={a.id} className="flex gap-3 text-sm"><input type="checkbox" checked={ids.includes(a.id)} onChange={e => setIds(v => e.target.checked ? [...v,a.id] : v.filter(id=>id!==a.id))} /><span>{a.published_title ?? a.title} · 网站第 {a.published_version} 版</span></label>)}
          <p className="text-sm text-ink-3">按勾选顺序排版，最多 10 条；有新草稿时仍使用已发布版本。</p>
          <Button tone="primary" type="submit" disabled={action.busy || ids.length === 0 || ids.length > 10}>生成公众号稿</Button>
        </form>
      </Card><Card title="最近出稿"><ul className="space-y-4">{exports.map(e => <li key={e.id}><Link className="text-accent" to={`?id=${e.id}`}>{e.title}</Link><p className="text-sm text-ink-3">{e.needs_update ? '原资讯已更新或撤回，请重新出稿；已发公众号文章也需检查。' : '对应网站版本未变更'}{e.published_url && <> · <a href={e.published_url} target="_blank" rel="noopener noreferrer">已发布公众号文章</a></>}</p></li>)}</ul></Card></div>
      {selected && <Card title={selected.title}>
        {selectedStatus?.needs_update && <p role="alert" className="mb-4 text-amber">这份稿件引用的版本已更新或撤回。请重新选稿，避免发布旧内容。</p>}
        <div className="mb-4 flex flex-wrap gap-3"><Button disabled={selectedStatus?.needs_update} onClick={() => void copyHtml()}>复制排版</Button><Button disabled={selectedStatus?.needs_update} onClick={() => download('html')}>下载 HTML</Button><Button disabled={selectedStatus?.needs_update} onClick={() => download('md')}>下载 Markdown</Button></div>
        <p role="status" className="mb-3 text-sm text-ink-3">{feedback}</p>
        <iframe title="公众号排版预览" sandbox="" srcDoc={selected.html} className="h-[520px] w-full rounded-control border border-line bg-white" />
        <details className="my-4"><summary>纯文本稿</summary><textarea readOnly aria-label="公众号 Markdown 稿" className="mt-2 h-72 w-full border border-line bg-bg p-3 text-sm" value={selected.markdown} /></details>
        <div className="my-4"><Button disabled={action.busy || selectedStatus?.needs_update} onClick={async () => { const r = await action.run<{url:string}>('POST', `/api/admin/editorial/exports/${selected.id}/website`, selected.edition, { success:'已发布网站简报' }); if (r) setFeedback(`网站简报已发布：${r.url}`); }}>{selected.edition.revision ? '审核并替换今天的网站简报' : '审核本期标题并发布网站简报'}</Button><p className="mt-2 text-sm text-ink-3">使用当前选稿和标题，每天一期；再次发布会保留旧版记录并替换今天的简报。公众号仍需单独发布。</p></div>
        <form className="space-y-3 border-t border-line pt-4" onSubmit={async e => { e.preventDefault(); await action.run('POST', `/api/admin/editorial/exports/${selected.id}/published`, { url: publishedUrl }, { success:'已记录公众号链接' }); }}>
          <label>公众号发布后的文章链接<Input required type="url" placeholder="https://mp.weixin.qq.com/s/…" value={publishedUrl} onChange={e => setPublishedUrl(e.target.value)} /></label><Button disabled={action.busy || selectedStatus?.needs_update}>记录已发布</Button>
        </form>
      </Card>}
    </div>
  </AdminPage>;
}
