# 仅采集公开 RSS（本地准备，未部署）

目标是后台查看原始候选。没有模型筛选、公众号稿、编辑版本、发布或投递；财务媒体可能含非 AI 内容，可在后台用标题关键词手动查找。候选并不代表已识别出“AI × 企业财务”交集。

`industry/collect-sources.json` 固定三个候选来源：Microsoft Dynamics 365 Finance、Journal of Accountancy、Accounting Today。只读其公开 RSS 响应；不访问正文页、不补图片、不调用 Jina/其他 provider，不绕过付费墙或 403。来源默认 disabled + isolated，全文公开开关关闭。原有行业示范源文件不变，专用脚本不会运行普通 seed 或 worker。

先应用增量迁移 `0041_collect_only.sql`（完整迁移仍使用 `node scripts/migrate.ts`），再在本地数据库中执行（DATABASE_URL 由操作者提供）：

```sh
MODEL_CALLS_ENABLED=false COLLECT_ENABLED=false node scripts/collect-only.ts --seed-only
# 下列命令会请求三个公开 RSS；生产执行须先获准开通这些来源的出站访问。
MODEL_CALLS_ENABLED=false COLLECT_ENABLED=false node scripts/collect-only.ts --run
```

注册是幂等事务，不覆盖后台已有来源；同名 ID 配置或隔离状态不符时整批回滚并报冲突。运行时拒绝 enabled、非 isolated、非 RSS 或配置含 feedUrl 之外字段的来源；CLI 还核对 feedUrl 必须与固定文件完全一致，拒绝数据库中被更换的地址。生产不允许私网抓取开关；任何来源被改成普通采集用途后，专用入口会拒绝整批执行。`sources.collect_only` 与 `articles.collect_only` 是持久保护标记，不是新的 participation_mode。数据库约束保证专用来源始终 disabled + isolated 且无公开全文权限；普通后台源修改、立即采集、强制 worker 抓取均拒绝它。通用 material 写入事务核对来源标记与专用入参一致；外部 ingest 对专用来源在更新健康状态之前拒绝，不能通过其它入口写入未标记记录或改写原文。文章标记跨修订保留，处理状态为 skipped；即使错误重置为 new，补偿扫描、入队、抽取、模型输入、归组、发布及后台内容修改均跳过/拒绝，来源重投影也不能创建审核或发布记录。已存在的非 collect-only URL（包括同源旧数据和跨源碰撞）不改变任何正文/状态/标记/审核或发布数据，只可补发现记录。`queue:false` 是强制参数；入口没有 worker/queueProcessing/settle/publish 路径。数据库事务和 advisory lock 防止批次重叠，失败整批素材与游标回滚，另记失败来源的健康状态及 fetch_runs，CLI 返回非零并输出错误。成功、失败和无可用条目的原因均可在信源后台查看。

整批最多处理 **3 条**（含重复检查），最多请求 3 个来源，每个响应最多 2 MiB，单个请求含重定向总超时 25 秒。只允许与初始 RSS 同源的重定向，每跳仍走 SSRF 防护。每个来源按记录位置轮转小窗口以逐步查看 feed 中的候选；有限 RSS 窗口、低吞吐及上游排序变化意味着不保证历史完整归档。重复 feed 内条目先去重；跨轮次/跨来源复用已有 URL identity 与修订规则。来源同一文章变化才产生新修订。

只保存 feed 自带文本，正文最多 20,000 字符，摘要最多 2,000 字符；不保存正文 HTML 和媒体。`/admin/content` 不填关键词即显示最近 50 条原始标题、来源、链接；详情显示有界纯文本。collect_only 详情没有编辑、发布或重跑按钮；普通历史 isolated 内容保持原行为，不误标为未经 AI 处理。详情展示原文/采集时间和字面关键词线索（AI/artificial intelligence/copilot/machine learning/LLM/人工智能/大模型；finance/financial/accounting/accountancy/CFO/audit/ERP/财务/会计/审计），不将线索当成模型筛选或相关性保证。接口仍使用原 admin 鉴权；没有新的写接口。

`deploy/collect-only/*.example` 是未安装的定时器方案；使用独立无登录采集 UID、固定版本目录及仅 DATABASE_URL 的配置，不复用 web/API UID 或 deploy 身份。占位路径/用户必须经审批替换；首批验证后才启用每小时一批。配置了 120 秒和 256 MiB 上限，但未进行生产压力/重启验收；上线与回滚步骤见 `docs/collect-only-rollout.md`。启用前须审阅代码和生产网络变更。现有 PREVIEW_MODE 的出站禁用与服务器网络策略均未绕过；保持当前个人预览时不具备公网采集能力。不要启动 worker，也不要把来源改 enabled 来驱动此入口。不要为本阶段开模型或添加 TokenPlan/Hermes 凭据。

验证：真实 PostgreSQL 17 与本地 HTTP fixtures 覆盖整批上限、短正文、重复去重、轮转、修订、零下游写入、来源/开关拒绝、同源重定向、跨域/SSRF/403 拒绝、管理员鉴权与返回长度。还验证老化后 sweep、后台 mutation、来源重投影都不新增下游记录；公开内容的 URL 碰撞不受影响。前端渲染测试验证脚本/图片/链接载荷只成为文本。测试命令：

```sh
DATABASE_URL=postgres://postgres@127.0.0.1:55432/aifinance_test MODEL_CALLS_ENABLED=false COLLECT_ENABLED=false node --test tests/collect-only.test.ts
npm run typecheck
npm run build -w @aihot/web
node --test apps/web/tests/*.test.ts
```

全套旧模型 mock 测试使用仓库测试预加载器：它在测试内打开必要的模型内存开关，同时拒绝所有非 loopback TCP 连接，子进程继承保护；collect-only 测试始终保持模型开关关闭。测试库名称必须以 `_test`/`_ci` 结尾，使用新空库迁移并 `node scripts/seed.ts --topics-only` 后运行：

```sh
NODE_OPTIONS='--import=./tests/loopback-only.mjs' DATABASE_URL=postgres://postgres@127.0.0.1:55432/aifinance_test MODEL_CALLS_ENABLED=false COLLECT_ENABLED=false npm test
```

不要为通过旧测试连接真实模型。
