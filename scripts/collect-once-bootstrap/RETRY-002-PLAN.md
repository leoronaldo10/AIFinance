# retry-002：本地审阅方案，尚无执行授权

本方案以用户提供的 v3 ECS 成功回执为准：passed/tests_passed/cleanup_complete=true，
cleanup_errors=[]，两种子进程 readiness/exit_verified/natural_exit=true，退出码均为 0。
诊断发布提交 c36f4f215fce492bff11250c434d2a5a91829b6f。
本补丁不要求重跑 v3，不发布、不访问 ECS、不启动采集。

## 本次补丁与保留边界

仅移植 v3 的 process_readiness 模块及生产适配器所需的等待、证据、退出逻辑；
不引入诊断安装器、控制器、会话框架。模块逐字节复用，保留全部安全判断。
运行期 ControlGroup 必须匹配；仅原 pidfd 已死亡且退出证据完整时允许 cgroup 消失。
RemainAfterExit=yes 保留退出元数据，不保持进程存活。探针仍是 PrivateNetwork sleep 30；
采集器仍由 systemd 限制 120 秒、runner 限制 105 秒，观察窗口 130 秒只等退出/收尾。
退出结果与身份同次读取，并再次完整核验；停止单元后按已核验 InvocationID 取摘要。

固定三源，每源最多一条、合计最多三条：
- collect-dynamics-finance / www.microsoft.com
- collect-journal-accountancy / www.journalofaccountancy.com
- collect-accounting-today / www.accountingtoday.com

三个源必须保持 enabled=false、participation_mode=isolated、collect_only=true。
256MiB、CPU50%、TasksMax32、原 UID/GID、能力集归零和 NNP 不变。
不调用 LLM，不运行 scheduler，不自动发布，不 seed/migrate，不修改站点 current。
网站 baseline 仍为 d57ba047369e666025347719caee1a4c642abe62；应用角色仍 SELECT-only。
采集运行包仍固定为 a88da42096a452d526e7cd53f6fdf26e6349cf1cd3d148428cefa9e73632656a。

## 独立轮次设计

1. 新审阅目录固定为 /root/aifinance-once-review-retry-002；新审计目录固定为
   /var/lib/aifinance-collect-once/retry-002。不要接受任意 --round/--state-dir 参数。
   原 review-socket、retry-001 的 started/state/backup/events/cleanup 回执及原 state.json
   保持原样。新目录必须专属且可信；有 started 标记时只读展示结果或恢复该轮清理，禁止再启动。
2. 固定入口 retry-002.py 已实现 install/check/run/cleanup/status。helper 固定为
   /root/aifinance-once-helper-retry-002/helper；所有模式都要求本地主机 root TTY、精确
   hostname 及外部审阅的 --manifest-sha256。安装只建立新 review，不修改单元/DB/网络。
   原模板以 retry-002-base-bootstrap.py.txt 和代码内 SHA256 固定；旧 review 所有模板
   精确比对后才生成新 review。仅 bootstrap、process_readiness 和单元的 RemainAfterExit
   是允许的差异。runtime、run.py、consume.py 不重打包、不替换。
   install 支持已完成安装的字节核验重入和正确 staging 半成品续装；不一致半成品保留并拒绝。
3. 执行前只读核查主机/用户、网站健康与 baseline、原尝试和 retry-001 清理完整、
   专用角色归属且已禁用、没有活跃采集进程、原备份/历史完整性、无并发写入者。
   当前现网状态本轮未读取；不能把历史结果当成最新状态。已有 same-boot 等证明若不成立，
   作为阻塞报告，不静默删除验证。
4. 原全局 /var/lib/aifinance-collect-once/consumed 必须不存在；若存在（含符号链接）立即拒绝。
   不删除、不移动、不改名、不改写它，也不创建替代路径绕过 consume.py。
   ready 和 database.env 必须已清理。使用原 consume.py 的 O_EXCL 原子 claim；
   无论成功失败，consumed 一旦产生永久保留。
5. 明确批准一次采集和独占写入窗口后，原子 mkdir 新审计目录并 fsync，写永久 started；
   将旧记录的只读快照/哈希、新配置哈希、备份和所有新证据仅写入 retry-002。
   不在 Operator 中按“哪个旧目录存在”猜测审计路径。二次调用不重复启动。
6. 新轮次先备份，再固定三域名公共 IPv4 的新快照；执行原无网络 sleep 探针的
   readiness 与自然退出核验，然后按下面已审批清单安装临时 HBA、nft、最小角色权限。
   单独 TCP/SCRAM 登录核验通过后才创建 ready 并启动一次 collector。
   DNS pin 保持 180 秒新鲜度；耗时超限时拒绝，不在已批准窗口内悄悄换地址。
7. 成功或失败均在 finally 中停止本轮单元、核验无剩余进程、禁用角色并撤销本轮权限、
   删除临时密码文件和 ready、只删除 nonce 归属匹配的 nft 表、按回执恢复 HBA/hosts。
   若并发修改 HBA/hosts，保留并发内容并报告清理不完整，不能覆盖它或继续新尝试。
   不删 consumed、started、旧/新备份或审计。恢复清理只能处理本轮已标记资源。
8. 验收原 InvocationID 的自然退出、唯一摘要、最多三条且三源仍 disabled/isolated/collect_only、
   允许表行差异合法、下游/发布/LLM 表无变化、应用仍只读、网站 baseline/健康正常。
   采集得到的数据保留；不自动恢复数据库备份或删除业务行。

## 真正执行前必须明确确认的变更

以下尚未获当前任务授权，也尚未在 ECS 执行。应连同本交付安装包、补丁和清单哈希一次性审阅。

| 范围 | 精确拟议动作 | 结束时恢复/核验 |
|---|---|---|
| 轮次与 systemd | 安装独立 review/helper、创建 retry-002 永久审计，备份并更新两份现有专用单元的 RemainAfterExit，daemon-reload；启动/停止 sleep 探针及最多一次 collector | 只停止本轮专用单元；不启用 timer，不自动重试；保留审计及安装记录 |
| 数据库 | 通过本机 postgres 管理 socket 操作 aifinance_preview:55432；复用已核验归属的 aifinance_collect_once，临时授予 grants.sql 的列级权限，LOGIN+随机 SCRAM 密码最长10分钟、连接上限1；执行备份和只读登录探测 | NOLOGIN PASSWORD NULL，执行原 revoke.sql 全部撤权，验证专用角色禁用；aifinance_app 不提权；备份保留 |
| HBA | 仅追加 `host aifinance_preview aifinance_collect_once 127.0.0.1/32 scram-sha-256`，使用独立 retry-002 标记和回执，校验配置并 reload（不 restart） | 比对原/新哈希及并发变化后恢复原字节、reload、核验加载；不可复用 retry-001 标记 |
| 联网 | root 仅解析上述三个域名，各1–8个公共IPv4；专用 UID 的 nft 仅放行 127.0.0.1:55432 与这批 IPv4:443，拒绝该 UID 其余流量；替换专用 hosts 快照并只读挂载，hosts:files；保持 TLS 与同源跳转限制 | 根据 nonce 删除专用 nft 表，按回执恢复 hosts；不改系统 DNS，不给 collector 放行 DNS、其他域名/子网/端口 |
| 一次采集 | 仅固定三源最多三条，最多120秒；独占写入窗口；无LLM/任务调度/发布 | 核对行差异与禁用标志、下游不变、网站健康、清理完成；保留本次业务记录和 latch |

grants.sql 的具体范围保持不变：数据库 CONNECT、public USAGE；sources SELECT 及
cursor/last_fetch_at/last_ok_at/health/fail_count/last_error/updated_at 列 UPDATE；
articles 中原清单列 SELECT/INSERT/UPDATE；article_revisions 指定列 SELECT/INSERT；
article_discoveries、fetch_runs 指定列 INSERT；fetch_runs_id_seq USAGE。
完整列名单以本补丁中未改动的 templates/grants.sql.in、revoke.sql.in 为准；
无 DELETE、DDL、role membership 或任何下游表写权限。三源/三条由固定程序与前后审计约束，
不把这些列级授权描述成数据库自带的三行上限。

## 入口、并发及中断恢复

这是完整本地待审阅包，未发布或在 ECS 上安装/执行；不再依赖手工替换旧 retry 入口。
文件分发采用完整 helper 归档和其外部 SHA256；不提供自行下载未审阅 commit 的逻辑。
未来授权安装后，将已验哈希归档放到固定 helper 路径，运行同一固定脚本的 install 模式。
该模式要求 --manifest-sha256 指定外部已审阅清单哈希，再校验所有包文件；脚本/归档本身
也应先按交付 SHA256 校验，不能只信归档内自带清单。归档不含 runtime，安装仅复制已验证旧运行包。

所有模式：`/usr/bin/python3 -I -B /root/aifinance-once-helper-retry-002/helper/retry-002.py MODE --manifest-sha256 REVIEWED_HASH`

- install：只生成独立 review。staging 路径为 /root/aifinance-once-review-retry-002.staging；
  逐文件精确校验、fsync、原子 rename。损坏或未知文件不覆盖；完整安装只核验重用。
- check：运行全部旧安全门及 retry-001 历史证明；不 claim，不启用角色，不改变 DB/HBA/nft/单元。
  允许三域名的只读解析、HTTP 健康探测和 nft 语法检查；各命令有超时。
- run：额外同时要求 --approve-retry-002-once --exclusive-writer-window；这两个参数只能用于 run，
  不从 install 隐式调用。没有参数直接拒绝，不先触发 DB 操作。只批准这一轮一次。
- status：报告 retry-002 是否 claim、claim 是否完整、是否采集完成；从不启动或恢复采集。
  completed 只表示采集步骤完成，整体结果还必须查看最新 cleanup 回执。
- cleanup：只恢复本轮，允许重复调用；不要求 consumed 不存在，不重做启动门，不启动采集。
  任意恢复失败仍尝试其余恢复步骤，输出独立错误分类和完整性结果；清理失败退出非零。

所有模式持有同一固定 /var/lib/aifinance-collect-once/retry-002.lock 的非阻塞 flock，
拒绝符号链接、不可信所有者/权限/硬链接；并发调用报 retry002_busy，不排队启动。
check/status 的唯一持久写入是首次创建这份锁文件；它不是消费标记。
原 retry-001 已有永久目录，会拒绝旧入口重跑；这不是能约束任意 root 手工 SQL 的数据库锁，
因此真实采集仍要求明确的独占写入窗口并核验其他数据库连接。

run 在全部旧门和历史检查后，再检查历史哈希及原 consumed/ready/密码文件缺席，
然后通过排他 mkdir claim retry-002。original-state、history、started、state 和 claim-complete
逐个 fsync；只有最后标记完整才可开始任何单元/DB/网络变更。中途崩溃留下的目录永久阻止
再次采集；缺少 claim-complete 时 cleanup 只保留并报告未开始副作用，不补写标记或续跑。

claim 后才将两份专用单元从“已核验旧字节”原子更新为“仅加 RemainAfterExit 的新字节”，
daemon-reload 后核验。回滚接受精确旧/新字节，因此可恢复只改完一份单元时的中断；
未知并发编辑保留并报错。运行结束或 cleanup 在进程确实停止后恢复两份原单元并 reload。

状态文件以同目录临时文件+原子 replace 保存，不复用旧 state.next，解决中断遗留
state.next 导致后续清理无法保存的问题；旧临时文件不删除。SIGINT/SIGTERM 触发 finally
清理，清理期间忽略重复信号；SIGKILL/断电须显式调用 cleanup，不自动再次采集。
HBA/hosts 在修改前先持久保存回执；恢复各自验证目标、旧/新哈希及并发编辑。
HBA 使用独立 retry-002 标记；不修改 retry-hba.py 的 retry-001 行为。

## 旧轮次未启动证明与拒绝条件

不能单凭 systemd 当前 MainPID=0 推断从未启动。本入口同时要求：

- 原 state.json 与 retry-001/original-state.json 一致；retry-001 started 为原永久标记；
  state.phase=disabled、相同 nonce/runtime，network_attempted/network_owned 均为 false。
- retry-001/events.jsonl 明确记录 retry_stopped/probe_identity_or_capabilities；不含已通过 TCP
  登录、batch_completed 或 retry_finished。最新 cleanup 回执 complete=true/errors=[]。
  旧代码顺序是 probe → HBA → activate → collector，此限定失败发生在激活和采集前。
- retry-001 的 HBA 回执不存在、备份哈希/大小匹配；resolver 回执若存在，当前 hosts 必须
  与其 before_sha256 一致。旧轮次全部文件哈希保存在新 history.json 并在清理后再次核验。
- 原 validate_never_started 的所有检查继续执行：全局 consumed/ready/密码不存在、
  immutable runner/latch 字节和模式匹配、collector ExecMainPID/启动时间为0、MainPID=0、
  inactive/static/no-restart/no-timer、专用角色归属与禁用证明、原备份匹配且属于本次 boot。

已解决的必然阻塞：旧 helper 将新版 bootstrap 与旧 review 直接比较；新版改为先用固定
旧模板验证全部旧内容，再生成独立新 review。预检在旧 review/旧单元配置下执行所有原门，
随后恢复新配置引用；claim 后只改两份单元的 RemainAfterExit。旧 retry-001 入口和目录不复用。
测试覆盖这条可通过路径以及旧门失败后仍拒绝、不产生新 claim 的路径。

仍属真正拒绝条件：重启导致原 same-boot 证明失效、日志/回执缺失或不符、consumed 已存在、
旧角色/单元/备份/配置变化、并发编辑、旧清理不完整。不得补造日志或删除旧 latch 使它通过；
遇到这些实际证据需另行审阅新的恢复依据。此次未读取 ECS，不能保证这些线上条件目前成立。

## 验证边界

新入口有离线文件/序列/并发锁测试，以及真实本机临时 PG17 的 retry-002 SCRAM/HBA
安装、独立标记、撤权、恢复、中断 reload 和并发编辑保留测试。root 所有权、系统单元
操作用明确 fixture 模拟，未冒充实机验证。原 v3 模块 SHA256 保持
f5ca1ad6788ca4365118ab06ceac433509837239761c0a8ce1e99ad896a447d6。
不触及前端，不需前端 build。v3 成功不代表真实 feed 连通或生产数据库写权限已验证。


## 已批准后的下载交接入口

retry-002-handoff.py 仅接受完整 commit SHA 和外部已审阅 SHA256SUMS 哈希。
供 ecs-user 在指定 hostname 的 TTY 中运行；先按固定 commit 从公开 raw.githubusercontent.com
下载全部 helper 文件，各请求30秒超时，验证清单与逐文件哈希。失败立即停止，不切换源站或放宽校验。
再经 sudo 捕获并复核全部下载字节，在固定 helper.staging 中逐文件 fsync、校验并原子安装。
不直接执行用户目录里的 retry-002.py；root 同时验证 handoff 自身属于指定清单。

首次交接按 install → check（包括 HBA 只读预检）→ run 顺序执行，任一步非零即停止。
每步打印 INSTALL_EXIT/CHECK_EXIT/RUN_EXIT 的真实退出码，最后 HANDOFF_EXIT；外层单行
命令另显示 HANDOFF_SHELL_EXIT，下载或校验失败同样保留非零状态。
根目录 /root/aifinance-once-helper-retry-002/handoff-results.jsonl 持久记录阶段退出码。

若 retry-002 目录已存在，再次运行相同交接命令只能执行 cleanup → status，不再 install/check/run。
因此断线后重跑同一固定命令不会再采一轮；cleanup 非零立即停止，保留全部现场和历史记录。
SIGHUP/SIGINT/SIGTERM 转发给执行子进程；执行入口在已 claim 的副作用阶段捕获这些信号并 finally
清理。SIGKILL、断电仍须重连后执行相同入口恢复清理，不自动恢复采集。
重复交接返回0只表示本次清理/查询成功，不将先前失败采集改报成功；查阅此前 RUN_EXIT、completed
及最新 cleanup 回执判断实际结果。交接本身也不保证真实 feed、DB 或所有前置条件通过。
