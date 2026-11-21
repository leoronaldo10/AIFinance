import { collectionEligibility, COLLECTION_STALE_MS, type CollectionOperations } from "@aihot/contracts/collection-operations";
import { AdminPage, Badge, Button, Card, Empty } from "./ui";
import { bj } from "./format";
const when = (value: string | null) => value ? bj(value, true) : "暂无记录";
const OUTCOME = { running: "记录进行中", ok: "抓取成功", failed: "抓取失败", skipped: "已跳过", unknown: "实际结果未知" };
const ERRORS = { limit: "额度或频率限制", timeout: "请求超时", tls: "证书或加密连接异常", network: "网络连接异常", access: "来源访问受限", source_format: "来源格式异常", other: "其他异常" };
const SERVICES = { active: "运行中", inactive: "未运行", failed: "服务失败", activating: "正在启动", deactivating: "正在停止", reloading: "正在重载", unknown: "未知" };
const ELIGIBILITY = { paused: "已暂停，没有下一次采集安排", unknown: "暂时无法确认下一次采集", worker_unavailable: "服务当前不可用，无法安排采集", eligible: "已到可采集时间，等待调度", waiting: "尚未到可采集时间" };
export function CollectionOperationsView({ data, now, refreshing, onRefresh }: { data: CollectionOperations; now: number; refreshing: boolean; onRefresh: () => void }) {
  const age = now - Date.parse(data.observedAt);
  const stale = !Number.isFinite(age) || age < -5_000 || age > COLLECTION_STALE_MS;
  const workerAge = now - Date.parse(data.worker.observedAt ?? "");
  const workerFresh = !stale && data.worker.state === "fresh" && Number.isFinite(workerAge) && workerAge >= -5_000 && workerAge <= COLLECTION_STALE_MS;
  const eligible = collectionEligibility(data, now);
  const serviceLabel = workerFresh ? data.worker.loadState === "not-found" ? "服务未加载" : data.worker.loadState === "masked" ? "服务已屏蔽" : SERVICES[data.worker.activeState] : data.worker.state === "stale" || (data.worker.observedAt && !workerFresh) ? "观测已过期" : data.worker.state === "missing" ? "尚未接入服务观测" : "服务状态未知";
  return <AdminPage title="采集状态（只读）" subtitle="Microsoft Dynamics 365 Finance · 不会启动采集、调用模型或发布内容" actions={<Button busy={refreshing} onClick={onRefresh}>刷新状态</Button>}>
    <p className="mb-4 text-sm text-ink-3" role="status">数据读取时间：{when(data.observedAt)}（北京时间）{refreshing ? " · 正在更新" : " · 页面可见时每 30 秒更新"}</p>
    {stale && <p role="alert" className="mb-4 rounded-control border border-hot/30 bg-hot-soft p-3 text-hot">页面数据已过期，不能据此判断当前是否运行。请刷新；若仍无更新，请联系维护人员。</p>}
    <div className="grid min-w-0 gap-4 md:grid-cols-2">
      <Card title="常驻服务">
        <Badge tone={workerFresh && data.worker.activeState === "failed" ? "bad" : "muted"}>{serviceLabel}</Badge>
        <dl className="mt-3 space-y-2 text-sm"><div><dt className="text-ink-4">服务观测时间</dt><dd>{when(data.worker.observedAt)}</dd></div><div><dt className="text-ink-4">开机启动</dt><dd>{workerFresh ? data.worker.unitFileState === "enabled" ? "已启用" : data.worker.unitFileState === "disabled" ? "未启用" : "未知或非独立启用单元" : "当前未知"}</dd></div></dl>
        <p className="mt-3 text-sm text-ink-3">进程运行不代表抓取成功。服务观测与下方的信源、抓取记录分别核对。</p>
      </Card>
      <Card title="信源与下一次采集">
        {data.sourceState === "ok" && data.source ? <>
          <Badge tone="muted">{stale ? "上次状态：" : ""}{data.source.enabled ? "已启用" : "已暂停"}</Badge>
          <p className="mt-3 text-sm">采集间隔：{data.source.intervalMinutes} 分钟</p>
          <p className="mt-2 text-sm font-medium">{ELIGIBILITY[eligible.state]}</p>
          {eligible.state === "waiting" && <p className="mt-1 break-words text-sm">下次可进入调度的时间：{when(eligible.at)}（北京时间）</p>}
          <p className="mt-3 text-sm text-ink-3">额度限制、排队或来源异常可能延后执行；这里不显示保证执行的倒计时。</p>
        </> : <Empty>{data.sourceState === "missing" ? "未查到指定信源，不能据此认为已暂停。" : "暂时无法读取信源和抓取记录，当前状态未知。"}</Empty>}
      </Card>
    </div>
    <section className="mt-5 min-w-0" aria-label="最近抓取记录">
      <Card title="最近抓取记录">
        <p className="mb-3 text-sm text-ink-3">发现条数是本次读到的候选；新增条数是去重后入库数。成功且新增 0 条仍是成功，不代表生成了草稿或已发布。</p>
        {data.sourceState !== "ok" ? <Empty>记录暂不可用。</Empty> : !data.runs.length ? <Empty>还没有该信源的抓取记录。已暂停的来源不会开始新的采集。</Empty> : <ul className="divide-y divide-line">
          {data.runs.map((run, i) => <li key={`${run.startedAt}:${i}`} className="grid min-w-0 gap-2 py-4 text-sm md:grid-cols-[1fr_1fr_1fr]">
            <div><strong>{OUTCOME[run.outcome]}</strong><p className="mt-1 text-ink-3">开始：{when(run.startedAt)}</p><p className="text-ink-3">结束：{when(run.finishedAt)}</p></div>
            <dl className="grid grid-cols-2 gap-2"><div><dt className="text-ink-4">发现</dt><dd>{run.foundCount ?? "未知"}</dd></div><div><dt className="text-ink-4">新增</dt><dd>{run.newCount ?? "未知"}</dd></div></dl>
            <div className="break-words text-ink-3">{run.errorCategory ? ERRORS[run.errorCategory] : run.outcome === "unknown" ? "记录缺失、未正常结束或格式异常；不能据此宣告成功。" : run.outcome === "running" ? "仅表示记录尚未结束。" : "无错误分类"}</div>
          </li>)}
        </ul>}
      </Card>
    </section>
  </AdminPage>;
}
