# 仅采集阶段上线审阅清单（未执行）

本文件准备下一次审批，未创建 UID、配置文件、服务、定时器或网络规则；没有发布代码、改数据库或签发 `native-ready`。本地功能测试不是生产 native-ready、压力测试或重启验收。

## 必须先获得的明确批准

- 批准最终补丁/提交、迁移 `0041_collect_only.sql` 与固定来源表。先发独立 feature 分支并跑 CI，不改 main/release。
- 新建或指定一个专用无登录采集 UID，只用于执行固定受审版本的 `scripts/collect-only.ts`。不用 web/API UID 989，不用 deploy 身份运行 JS；不给应用 UID 989 放网。
- 向专用 UID 提供只含现有 `DATABASE_URL` 的受保护配置文件。它取得了新的持久数据库访问权限，须单独批准；不复制整份应用 `.env`，不含管理员、模型或集成凭据。不需要新数据库账号、SSH key 或监听端口。
- 批准专用 UID 的必要 DNS/HTTPS 出站策略，以及仅在这个新进程中关闭 PREVIEW_MODE 出站总禁令。web/API 的个人预览配置与现有隔离保持不变。应用代码固定 3 个 RSS URL、逐跳 SSRF 和同源规则，并不等于内核实现了域名白名单；具体网络规则仍须结合现有主机策略单独审阅，本文不生成或应用规则。

## 最小执行顺序

1. 核验不可变提交、release 目录与制品 SHA-256；审阅新增数据库列和约束。迁移前备份/恢复条件由既有数据库维护流程负责，不在此修改备份策略。
2. **单独审阅迁移与一次性切换路径。** 仓库当前 `deploy/native/release.sh` 要求既有 native-ready，且 shared/new/current 三份 schema 指纹相同。本补丁增加迁移，不能声称能直接走常规 release。不得伪写 native-ready，不得改旧 release 的 schema 指纹来绕过检查。若父线程已有受审的一次性升级权限，可另审“应用 0041 + 固定版本切换 + 验证”的具体命令而不开放常规 deploy；当前未验证该生产路径，本文不是其执行批准。
3. 用已批准的专用 UID、DB-only 配置和固定版本执行 `node scripts/collect-only.ts --seed-only`。该命令不发 HTTP；同名来源冲突即报错并回滚，不能强改旧活跃源。确认三个来源都是 collect_only、disabled、isolated，公开全文开关关闭。
4. 由管理员替换 `deploy/collect-only/collect-only.service.example` 的用户/路径，先 `systemd-analyze verify`，安装 oneshot **但不启用 timer**。模板限制 120 秒、256 MiB、32 tasks、只读系统、无额外权限；这些资源限额未做生产压力验证。网络与 DB 配置按单独批准的方案提供。
5. 在其它作业不运行或能准确归因的验收窗口记录行数/任务快照，启动一次 oneshot。整批处理最多 3 条，新增和修订合计不能超过 3；只访问固定公开 RSS，最多每源 5 次同源重定向，不补正文/图片，不绕过 403。成功时检查 fetch_runs 的处理数、原因和后台纯文本展示；失败时素材/游标整批回滚，失败健康记录与 journal 保留。
6. 核对 articles/article_revisions 增量，所有新文章 collect_only=true、processing_state=skipped；此批 jobs、analyses、receipts、editorial_*、publications、deliveries 不得新增。有并行旧业务时不能仅用全表总数归因，要按 article/source/job data 核对；不要把其他业务增量误判成本批副作用。页面验证标题、来源、原文链接、文章/采集时间、字面关键词线索及截断提示，无编辑/发布/重跑按钮。原文链接由管理员主动点击，服务不抓正文页。
7. 首批验收成功后，才在已批准范围启用 hourly timer。若需要重启/故障恢复验收，先安排单独窗口执行并记录；目前没有验证重启后定时器、生产内存或压力表现。

受审参数替换后，操作形态如下（占位符未填，不能照抄执行）：

```sh
# 使用已受审、只含 DATABASE_URL 的 EnvironmentFile；不要把凭据贴进命令或输出。
# 注册源：由同一专用 UID / 同一固定版本运行 --seed-only（可用临时 oneshot 替换参数）。
systemd-analyze verify /REVIEWED/collect-only.service /REVIEWED/collect-only.timer
# 安装路径和权限先按主机管理约定审阅，之后才 daemon-reload。
systemctl start collect-only.service
systemctl status collect-only.service --no-pager
journalctl -u collect-only.service --since 'APPROVED_FIRST_RUN_TIME' --no-pager
# 验收通过且授权覆盖定时执行后：
systemctl enable --now collect-only.timer
```

## 停止与回退边界

先停并禁用 timer，再停 oneshot：`systemctl disable --now collect-only.timer`、`systemctl stop collect-only.service`。按审阅记录只撤销本次新增的专用 UID 出站权限和 DB-only 文件读取权限，不动 UID 989、旧防火墙规则、原 release 或已有数据库账号。来源继续 disabled + isolated。

保留加性 schema、原始材料与隔离守卫，不删除文章来“回滚”。一旦已存入 collect-only 数据，旧版代码不认识这些标记；不能把直接回滚到旧应用当作安全停止方案。若必须回滚应用，应保留隔离守卫的修复版本，或在停 worker/限制后台写操作的维护窗口单独审查数据隔离方案；不得将这个问题掩盖为已验证的自动回滚。
