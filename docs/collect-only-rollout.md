# 仅采集一次性升级与安装审阅单（默认 check-only）

这是 `e6f84e81b17f1d916e9f5024769fe8af737b2315` 旧预览到本 PR 最终受审提交的**执行前审阅方案**，不是生产执行授权。新提交 SHA、制品 SHA256、操作者、维护窗口和证据路径必须填入审批记录；不得用可移动分支代替固定 SHA。timer 默认不安装、不启用。没有创建生产身份、读取真实 env、改网络、迁移、切换服务或写 ready。

## 唯一可直接运行的检查入口

`node scripts/collect-only-check.ts`（也接受 `--check`）只在一个 repeatable-read/read-only 事务中读取显式 `DATABASE_URL` 指定的数据库；拒绝 `--apply`，不迁移、不 seed、不 fetch、不启动 worker。输出迁移账本、隔离列/约束、固定来源状态和表计数，不输出凭据、正文或配置。counts中不存在的表是 `null`，不能当作零；账本/sources/articles等基线必需表缺失则检查失败。每条查询限时 10 秒；大表查询超时即停止，不取消超时来强跑。它兼容 0041 前后的 schema，**成功也始终返回 readyForApply=false**。

由已批准的数据库配置加载方式注入变量，保存 JSON 到受保护证据目录；不要 `source` 不可信 env、把 URL 放命令行或复制整份应用 env。该入口不证明备份可恢复、网络受控、内核资源限额、应用健康或可安全切换。

## 为什么没有自动 apply

现有 `deploy/native/release.sh` 要求 native-ready 以及 shared/new/current 三份 schema 指纹一致；0041 使其不再满足。`first-preview.py start/stage` 只允许首次空库/无 current 安装，不能用于已有站点。`scripts/migrate.ts` 除迁移外还会调用 `publishArticle` 回填编辑审核状态，**本阶段禁止将它直接用于生产升级**。没有已核实的生产一次性升级入口、备份恢复记录和专用采集网络策略，不能可靠生成自动 apply 或伪造可直接粘贴的服务器命令。

最大限度复用已有边界：`package.sh` 生成干净固定提交的制品；受审 `extract-release.py` 处理归档；`first-preview.py` 的 `schema()` 验证完整迁移清单和文件哈希，`health()` 验证 release SHA，`resource_evidence()` 验证现有 API/Web/DB 的实际 UID 和 cgroup v1。这些函数是给受审操作入口复用的代码，不意味着可用 `first-preview.py start` 绕过首次安装条件。不扩展 SSH gateway/sudo，不改旧 schema 指纹，不伪写 native-ready。

## 用户一次批准的具体范围

一次批准可以覆盖下列有条件顺序，无需每步再问；操作前父线程仍须填完并审阅具体命令和路径。任何前置条件失败即停，不把失败解释为扩大权限授权。

- 最终 CI 绿灯提交及归档 SHA256、仅迁移 0041、维护窗口、备份/恢复方案、固定版本切换与下面的失败边界。
- 专用无登录采集 UID（不是 UID989 或 deploy），现有 DATABASE_URL 的 DB-only 文件读取权，以及仅该 UID 的受审 DNS/HTTPS 出站方案；不新建 DB 账号、SSH key 或监听端口，不给 UID989 放网。
- 安装受审 oneshot、先无网络资源探针、一次 seed、一次最多 3 条采集及后台验收；**不启用 timer**。定时自动运行只有批准明确包含“验收通过后启用每小时 timer”才可执行。

## 最小人工步骤（每行一个操作，须按顺序）

以下是完整的操作任务，不是缺少真实参数仍宣称可用的 shell 命令；执行者必须以已批准的服务器入口落实。当前只做本地 fixture。

1. **只读基线：**记录当前 release=e6、数据库身份、迁移账本/旧文件哈希、所有写进程与 timer 状态、只读计数；比对 e6 与新制品清单，确认唯一待迁移是 `0041_collect_only.sql`，旧文件逐字节不变，存在任何未知/缺失迁移则停。
2. **固定制品：**在 CI 绿灯且工作区干净的固定 SHA 上运行现有 `package.sh`，记录归档 SHA256；用已受审 extractor 在 deploy 身份下解压到新不可变目录，核验 RELEASE_SHA、构建文件/依赖及完整 schema 清单；不执行上传 JS 为 deploy/root，不覆盖旧 release。
3. **维护/备份：**先停止本应用所有数据库写入口（含后台写请求、worker、旧采集、timer；实际 unit 必须已核实），再用现有数据库维护身份做 PG17 custom-format 一致性全库备份及角色/扩展/权限恢复记录；备份0600、哈希/大小/空间/时间记录齐全，放在 release 之外。
4. **恢复演练：**用 PG17 `pg_restore --exit-on-error` 将备份恢复到隔离空验收库（无生产服务连接），核对全部迁移账本、角色/扩展需求、关键表精确计数及抽样内容；仅 `pg_restore --list` 不算恢复证明；磁盘不足、恢复失败或无法给出实际恢复目标/时限则不迁移。
5. **仅 0041：**受审维护入口先持有既有 `state/release.lock` 文件的同一flock并贯穿步骤5至8（不能用无关PG advisory lock代替）；数据库维护会话开启一个事务，设 `lock_timeout='5s'`、`statement_timeout='60s'`，按制品原文执行0041并同事务插入对应 schema_migrations 行；前置账本/列状态必须与步骤1相符，禁止调用带审核回填的 migrate.ts；任一错误回滚整个事务，停止且不切版本。
6. **迁移后检查：**重新运行 check-only，核验两列 false默认/NOT NULL、CHECK convalidated=true、唯一新增迁移行、原表计数/原记录默认标记不变；不得更新旧 release 的 schema.sha256，不将常规 release.sh 当本次升级入口。
7. **一次性切换：**在另行审阅且使用既有权限的维护入口内原子切换 current 至固定新目录并重启已核实 API/Web 两个 unit；只在迁移确认后更新本次 shared schema 记录，保留旧指纹及证据；不签发 ready、不改变普通部署资格；若当前权限无法完成此受审步骤则停，不扩权。
8. **应用验收：**复用 health 验证 API 返回精确新 SHA、Web 正常、管理员登录/最近列表正常，UID989出站隔离保持；collector仍未 seed/run，后台写维护门禁维持到应用验收结束。
9. **最小采集安装：**按批准创建/指定无登录采集 UID、DB-only 文件（root拥有、仅该UID可读、不可写、目录无旁路权限）、固定 Node/release路径；清空 Node注入/proxy/模型凭据等额外环境来源，使用 service 模板的安全阀；文件只有 DATABASE_URL，不复制应用 env；先安装无网络资源探针，不装 timer。
10. **资源实测：**按下节读取探针的真实 PID/UID、systemd属性和 cgroup v1内核计数；通过后移除探针，安装 oneshot（256MiB/32tasks/120秒），核对实际 unit内容与受审模板；语法检查不代替实测，失败即停。
11. **seed：**在同一受审 unit约束、同一UID/DB-only配置/固定版本下，将一次性 ExecStart参数换成 `scripts/collect-only.ts --seed-only` 执行一次，成功后恢复 `--run`；确认正好三个固定来源 disabled+isolated+collect_only，两个fulltext开关false，同名冲突则停，禁止强改旧源。
12. **首次 run：**停止/隔离其它写入并保存 check-only前快照，批准专用UID出站后启动一次oneshot，同时采集PID/内核证据，结束保存journal/exitcode/fetch_runs与check-only后快照；失败不重试绕403，先诊断，素材/游标事务应回滚而失败健康记录可新增。
13. **验收/结束：**按下节逐项核对首次批次与后台，只读展示通过后解除应用维护门禁；保留timer未安装状态，只有批准明确覆盖且首批验收通过才安装/启用hourly timer；重启与压力验收另留证据，不宣称已完成。

## systemd 239 / cgroup v1 必须实测的资源证据

模板使用 `MemoryAccounting=yes`、`MemoryLimit=256M`（268435456字节），不用仅适用于另一种层级的假定；并设 TasksMax=32、TimeoutStartSec=120、NoNewPrivileges、空 CapabilityBoundingSet/AmbientCapabilities、ProtectSystem/ProtectHome、PrivateTmp、LimitCORE=0。目标服务器同类现有unit使用MemoryLimit，但这不是新采集unit已生效的证据。

先由操作人员在同一采集 UID 与相同unit约束下运行可信 `/usr/bin/sleep 30` 无网络探针（无DB env、无JS），保留足够读取窗口；探针unit名与实际路径需受审。实际采集时重复抓取资源证据；短任务PID消失不能记作通过，可在下次批准的单次运行中重新采样，不为取证取消资源限制。

- `systemctl show` 记录 MainPID、User、MemoryAccounting、MemoryLimit、TasksMax、TimeoutStartUSec、Result；属性声明必须与内核证据一致。
- `/proc/PID/status` 四个Uid字段都是专用UID、NoNewPrivs=1、CapEff=0；PID不能是989、deploy、root。
- `/proc/PID/cgroup` 的memory路径必须是该unit；在 `/sys/fs/cgroup/memory/该路径/` 确认PID在cgroup.procs，memory.limit_in_bytes=268435456，usage/max_usage低于限额，failcnt未增；读取前后MainPID一致。
- pids控制器的相同unit路径中 `pids.max=32`、pids.current≤32；控制器不存在或不支持就停，不把TasksMax文本当生效。
- 记录oneshot的执行耗时≤120秒、Result=success、ExecMainStatus=0；Timeout/OOM/failcnt增长均不通过。探针与一次采集不等于压力或重启验收。

本地容器PID1不是systemd，`/proc/self/cgroup`是v2；只能验证模板与fixture，不能实测生产systemd239/cgroupv1，不能签发ready。

## 首批计数与页面验收

暂停其它写入的验收窗口内，对比两份check-only JSON：articles增量0..3、article_revisions增量0..3（每次新建也创建revision，**不能把两张表增量相加当作处理数**）；CLI返回各源processed之和≤3，created+revised≤processed，旧URL可只增加discovery。新文章collect_only=true且processing_state=skipped。

以下表精确计数增量全部为0：pgboss.job、analyses、receipts、editorial_overrides、editorial_review_state、editorial_versions、editorial_exports、publications、deliveries、grouping_decisions。若pgboss.job为null，确认前后都不存在且worker没启动，不能写“队列0条”；其余必需表null则验收失败。若不能隔离并发写入，必须按article/source/job data归因，而不是比较全表数硬判通过。

fetch_runs可增加、sources健康/游标可变化、discovery可增加；保留403/空源原因。管理员确认标题、来源、原文链接、文章/采集时间、RSS有界纯文本和字面关键词线索，无编辑/发布/重跑动作；未登录应被拒绝。只访问RSS，不自动跟文章链接。当前是原始财务候选，不声称已筛成AI×财务交集。

## 失败回退边界

迁移事务失败：不切换、不seed，保留原服务/备份；核对账本后才审阅重试。迁移成功而新应用未通过：collector保持关闭，维护门禁不解除，只有确认无collect-only材料且备份恢复与旧应用兼容的独立审阅方案才允许回旧版本；不得依赖release.sh自动回退。

一旦已采集：先停/禁用timer（若未安装则记录不存在），再停oneshot并撤销本次专用UID的新出站及DB-only读取权；不动UID989或旧规则。保留加性schema/素材和守卫代码，不能盲退到不识别标记的旧应用，也不能靠删除文章“回滚”。必须修复则用保留守卫的版本；全库恢复会丢失备份后的写入，须单独确认损失窗口并重新验收。

## 来源预期（非生产验收）

见 [公开来源检查记录](collect-only-sources-check.md)。初批顺序/内容随RSS变化，固定三个来源按剩余额度分配，首源最多1条，后续来源可承接空源余量，不能承诺每源恰好一条。当前fixture证明解析和入库，不证明生产出口已获准或源站永远可达。
