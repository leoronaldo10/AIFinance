import type { FinanceInsight as Insight } from "@aihot/contracts/editorial";
import { AVAILABILITY_LABELS, EVIDENCE_LABELS } from "@aihot/contracts/editorial";
import { Link } from "react-router";

export function FinanceInsight({ insight: f }: { insight: Insight }) {
  return <section aria-label="财务视角解读" className="my-8 space-y-5 rounded-2xl border border-line bg-surface p-5 sm:p-7">
    <div className="flex flex-wrap gap-2"><span className="chip bg-accent-soft text-accent">{AVAILABILITY_LABELS[f.availability]}</span><span className="chip">{EVIDENCE_LABELS[f.evidence]}</span></div>
    {[["财务为什么关注", f.relevance], ["现在能不能用", f.conditions], ["可以怎样尝试", f.nextStep], ["限制与依据", f.limitations]].map(([label,text]) => <div key={label}><h2 className="mb-2 text-base font-semibold">{label}</h2><p className="whitespace-pre-wrap text-[15px] leading-7 text-ink-2">{text}</p></div>)}
    <div className="flex flex-wrap gap-2">{f.scenarios.map(s => <Link key={s} to={`/all?tag=${encodeURIComponent(s)}`} className="chip">{s}</Link>)}</div>
  </section>;
}
