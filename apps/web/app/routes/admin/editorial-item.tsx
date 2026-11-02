import { useEffect, useState } from "react";
import { Link } from "react-router";
import type { Route } from "./+types/editorial-item";
import type { EditorialCopy, EditorialDetail, FinanceInsight } from "@aihot/contracts/editorial";
import { AVAILABILITY_LABELS, EVIDENCE_LABELS } from "@aihot/contracts/editorial";
import { CATEGORIES } from "@aihot/industry/taxonomy";
import { adminGet } from "../../lib/admin.server";
import { useAdminAction } from "../../features/admin/action";
import { AdminPage, Button, Card, Input } from "../../features/admin/ui";

export async function loader({ params, request }: Route.LoaderArgs) { return adminGet<EditorialDetail>(request, `/api/admin/editorial/${encodeURIComponent(params.id)}`); }
const blank: FinanceInsight = { relevance: "", scenarios: [], availability: "unknown", conditions: "", nextStep: "", limitations: "", evidence: "announcement" };
const textClass = "mt-1 min-h-24 w-full rounded-control border border-line bg-bg p-3 text-sm leading-relaxed";

export default function EditorialItem({ loaderData: detail }: Route.ComponentProps) {
  const current = detail.versions[0]!;
  const [copy, setCopy] = useState<EditorialCopy>(current.copy);
  const [note, setNote] = useState("");
  const [viewVersion, setViewVersion] = useState(current.version);
  const action = useAdminAction();
  useEffect(() => { setCopy(current.copy); setNote(""); setViewVersion(current.version); }, [current.version, detail.articleId]);
  const finance = copy.finance ?? blank;
  const changeFinance = (patch: Partial<FinanceInsight>) => setCopy(c => ({ ...c, finance: { ...(c.finance ?? blank), ...patch } }));
  const dirty = JSON.stringify(copy) !== JSON.stringify(current.copy);
  const historical = detail.versions.find(v => v.version === viewVersion) ?? current;
  const base = `/api/admin/editorial/${detail.articleId}`;
  const review = (kind: string) => action.run("POST", `${base}/review/${kind}`, { version: current.version, note }, { success: kind === "approve" ? "已审核并发布网站版" : kind === "withdraw" ? "已从网站撤回" : "已退回稿件" });
  return <AdminPage title="核对与编辑" subtitle={`当前第 ${current.version} 版${detail.publishedVersion && !detail.withdrawn ? `；网站正在使用第 ${detail.publishedVersion} 版` : "；尚无公开版本"}`}>
    <div className="mb-5 flex gap-4"><Link to="/admin/editorial">← 审核队列</Link><Link to={`/admin/content/${detail.articleId}`}>处理记录与重新生成</Link>{detail.publishedVersion && !detail.withdrawn && <Link to={`/items/${detail.articleId}`}>查看网站版</Link>}</div>
    <div className="grid items-start gap-6 xl:grid-cols-2">
      <Card title="原文依据与版本">
        <a href={historical.evidence.url} target="_blank" rel="noopener noreferrer" className="break-all text-accent">{historical.evidence.url}</a>
        <p className="my-3 font-medium">{historical.evidence.title}</p>
        <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-words text-sm leading-relaxed text-ink-2">{historical.evidence.text || "尚未取得正文，请补充可靠材料后审核。"}</pre>
        <label className="mt-5 block">历史版本<select className="ml-3 rounded border border-line bg-bg p-2" value={viewVersion} onChange={e => setViewVersion(Number(e.target.value))}>{detail.versions.map(v => <option key={v.version} value={v.version}>第 {v.version} 版 · {v.status === 'approved' ? '已审核' : v.status === 'rejected' ? '已退回' : '待审核'}</option>)}</select></label>
        <div className="mt-3 rounded-control bg-bg p-3 text-sm"><strong>{historical.copy.title}</strong><p className="my-2 whitespace-pre-wrap">{historical.copy.summary}</p><p>{historical.copy.finance?.relevance}</p><p className="mt-3 text-ink-3">{historical.note || "自动整理草稿"}</p></div>
      </Card>
      <Card title="财务读者看到的内容">
        <form className="grid gap-4" onSubmit={async e => { e.preventDefault(); await action.run("POST", `${base}/edit`, { version: current.version, copy, note }, { success: "已保存新版本，请再次核对后审核" }); }}>
          <label>标题<Input required maxLength={300} value={copy.title} onChange={e => setCopy(c => ({ ...c, title: e.target.value }))} /></label>
          <label>发生了什么<textarea required className={textClass} value={copy.summary} onChange={e => setCopy(c => ({ ...c, summary: e.target.value }))} /></label>
          <label>栏目<select required className="ml-3 rounded border border-line bg-bg p-2" value={copy.category ?? ""} onChange={e => setCopy(c => ({ ...c, category: e.target.value || null }))}><option value="">请选择</option>{CATEGORIES.map(c => <option key={c.key} value={c.key}>{c.label}</option>)}</select></label>
          <label>财务为什么关注<textarea required className={textClass} value={finance.relevance} onChange={e => changeFinance({ relevance: e.target.value })} /></label>
          <label>适用场景（用顿号分隔）<Input required value={finance.scenarios.join("、")} onChange={e => changeFinance({ scenarios: e.target.value.split("、").map(s => s.trim()) })} /></label>
          <label>可用性<select className="ml-3 rounded border border-line bg-bg p-2" value={finance.availability} onChange={e => changeFinance({ availability: e.target.value as FinanceInsight['availability'] })}>{Object.entries(AVAILABILITY_LABELS).map(([k,v]) => <option key={k} value={k}>{v}</option>)}</select></label>
          <label>使用条件：地区、版本、费用或 IT 配合<textarea required className={textClass} value={finance.conditions} onChange={e => changeFinance({ conditions: e.target.value })} /></label>
          <label>可以怎样尝试<textarea required className={textClass} value={finance.nextStep} onChange={e => changeFinance({ nextStep: e.target.value })} /></label>
          <label>证据类型<select className="ml-3 rounded border border-line bg-bg p-2" value={finance.evidence} onChange={e => changeFinance({ evidence: e.target.value as FinanceInsight['evidence'] })}>{Object.entries(EVIDENCE_LABELS).map(([k,v]) => <option key={k} value={k}>{v}</option>)}</select></label>
          <label>限制与依据（实测请注明出处和条件）<textarea required className={textClass} value={finance.limitations} onChange={e => changeFinance({ limitations: e.target.value })} /></label>
          <label><input type="checkbox" checked={copy.selected} onChange={e => setCopy(c => ({ ...c, selected: e.target.checked }))} /> 放入首页精选</label>
          <label>编辑／审核说明<Input required value={note} onChange={e => setNote(e.target.value)} placeholder="说明修改依据或审核结论" /></label>
          <div className="flex flex-wrap gap-3"><Button type="submit" disabled={action.busy || !dirty}>保存新版本</Button><Button type="button" tone="primary" disabled={action.busy || dirty || !note.trim() || current.status === 'rejected'} onClick={() => void review('approve')}>审核并发布网站</Button><Button type="button" disabled={action.busy || dirty || !note.trim() || current.status !== 'draft'} onClick={() => void review('reject')}>退回</Button>{detail.publishedVersion && !detail.withdrawn && <Button type="button" disabled={action.busy || dirty || !note.trim()} onClick={() => void review('withdraw')}>撤回网站版</Button>}</div>
          {dirty && <p className="text-sm text-ink-3">修改尚未保存。保存后再审核，网站上已发布的版本会保留。</p>}
        </form>
      </Card>
    </div>
  </AdminPage>;
}
