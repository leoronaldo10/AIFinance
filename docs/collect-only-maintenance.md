# d57 仅采集：一次性维护入口

本文与 `collect-only-rollout.md` 的审阅边界配套。现在提供两个可执行 Python 3.6.8 维护入口；**有代码不等于目标机已验收**。默认 `check` 只读，实际 apply 仍由获授权的管理员在阿里云 root 网页终端执行。不要把下文含 `ARCHIVE_SHA256` 的示例当成已填写的生产命令。

## 固定范围与制品

- 旧应用：`e6f84e81b17f1d916e9f5024769fe8af737b2315`
- 新应用：`d57ba047369e666025347719caee1a4c642abe62`
- 本次维护代码与应用版本分开审查。维护 helper 的后续提交不改变上述应用目标；不 merge main，不自动移动 release 分支，不扩展 gateway/sudo/CI permissions/Environment/secrets
- 两版原有 37 个迁移字节完全相同，唯一新增为 `0041_collect_only.sql`，SHA256 `a71db6b66e9dfc862d60df2199e37e4baab13f1ba20056011984b33059b7ecef`
- 旧、新完整 schema 清单 SHA256 分别为 `33662b6612b0ce65eacd9c783e98da9b07835f90c03847b01430aec6ccfa85cb`、`405672156ea4ef49bc9272d47f23de3a7208a8c80a9d2bee066e6d607152cafc`
- build run `37089384282` / artifact `11262220799` 的 d57 tar.gz SHA256 为 `0f0d78343f1505251a4e0b5cb92e33c4a1e2eda1b7b94bb1a3bcbbb5aec24bf7`。这不是 GitHub 外层 ZIP 的 SHA256。**stage 会重新构建：必须使用那次 STAGED_ONLY 输出并与其 artifact 复核的 tar.gz SHA256，不能沿用另一次 build 的值**

现有 `.github/workflows/deploy-preview.yml`：`build` 无 SSH；`stage` 必须以 `release/aifinance-preview` dispatch，目标 d57 必须是该 release 分支祖先，随后需要现有 Environment 审批。`stage` 只上传到 `/opt/aifinance/incoming/d57....tar.gz`。此次禁止选择 `deploy`、`rollback`，也不调用 `release.sh` 或 `first-preview.py start`。

## 安装受审 helper

管理员须从维护提交的完整固定 SHA 下载这两个文件，先用父线程提供的文件 SHA256 核对，再独占安装为 root:root 0755：

- `deploy/native/collect-only-upgrade.py` → `/opt/aifinance/bin/collect-only-upgrade.py`
- `deploy/native/collect-only-runner.py` → `/opt/aifinance/bin/collect-only-runner.py`

父线程提供实际填完 URL、提交 SHA、文件校验和的完整单行安装命令；不要求用户自行拼片段。下载不是执行；哈希不符、已有同名文件、目录不是 root 管理均停止。不要把应用 env 或凭据贴入命令、上传或聊天。

## 顺序与实际行为

每行单独执行，前一步成功且证据审阅通过才继续。`ARCHIVE_SHA256` 必须由本次 stage 的实际制品替换。

1. `/usr/bin/python3 -I -B /opt/aifinance/bin/collect-only-upgrade.py check --archive-sha256 ARCHIVE_SHA256`
2. `/usr/bin/python3 -I -B /opt/aifinance/bin/collect-only-upgrade.py apply --archive-sha256 ARCHIVE_SHA256`
3. 应用健康通过后，管理员查看后台登录、最近列表。接着 `/usr/bin/python3 -I -B /opt/aifinance/bin/collect-only-runner.py check`
4. `/usr/bin/python3 -I -B /opt/aifinance/bin/collect-only-runner.py install`
5. `/usr/bin/python3 -I -B /opt/aifinance/bin/collect-only-runner.py probe`
6. `/usr/bin/python3 -I -B /opt/aifinance/bin/collect-only-runner.py seed`
7. `/usr/bin/python3 -I -B /opt/aifinance/bin/collect-only-runner.py run`
8. 管理员确认首批后台标题、来源、原文链接、日期、RSS 有界纯文本正常，未登录被拒绝，没有编辑、发布或重跑动作。只有该验收通过、原批准包含每小时运行时，执行 `/usr/bin/python3 -I -B /opt/aifinance/bin/collect-only-runner.py enable-hourly --accept-admin-view`

停止/隔离采集：`/usr/bin/python3 -I -B /opt/aifinance/bin/collect-only-runner.py disable`。该动作停止采集并禁用 timer，撤销专用 DB 文件组读取和 HTTPS 出站；不会删除素材、回退 schema、改 UID989 的规则或旧 8000 服务。没有自动重新启用或绕过失败重试入口。

### Upgrade check

只读核对 root helper、既有 UID、PG17.11 二进制、实际 unit 文件/FragmentPath/无 drop-in、精确旧 current/无 pending current/无 native-ready、旧 schema 全清单和真实账本、尚无 collect-only 列、应用健康和既有 egress guard、incoming 制品 SHA256，以及备份+恢复+新制品空间/内存预留。unit 与受审模板不一致时停止并审查实际差异，不要求为了通过测试改无关设置。返回 `readyForApply=false`；此检查不能代替真实恢复演练。

### Upgrade apply

- 持有既有 `state/release.lock` 的同一 flock；拒绝缺失/替换锁，不覆盖它
- 将已核验上传制品复制到 root-owned `/opt/aifinance/maintenance-inputs`，再次核对复制后 SHA256；只有 deploy 身份运行现有受审 extractor，绝不执行上传 JS 为 deploy/root
- 新 release 用 nofollow 文件描述符冻结为 root-owned 只读树。既有受限 deploy 身份及其目录重命名权仍属信任边界；不新增其能力、不更改现有 releases 父目录归属
- 只停止 API/Web 两个 unit；DB、既有 egress 和旧 8000 保持。检查无 UID989 进程、无其它数据库会话、无未知活跃 aifinance unit/timer。管理员仍须确认无另名 cron/外部写入器；不能仅凭瞬时会话为零证明不存在将来的外部写入
- 以实际非超级用户应用登录读取表计数、完整逐行内容哈希、旧账本、owner/ACL/extension/role/sequence 元数据。禁止读取或记录角色密码哈希。单次输出超过1MiB或查询超时即停，大表触发此上限不等于备份损坏，不能取消边界强跑
- PG17 custom-format 全库备份为 root-only 0600，立即持久化哈希/大小/时间和基线证据，位置 `/var/backups/aifinance-collect-only/<run-id>`
- 独立短期 PG17 恢复单元以现有应用 OS UID989 运行、PrivateNetwork、只允许 AF_UNIX、无 TCP listener、私有 0700 socket、空 caps/NNP、MemoryLimit256MiB/Tasks32/240秒上限。隐藏生产 env、生产数据目录及 DB socket；不传生产密码，不改 HBA。临时集群的数据库超级用户不能访问生产服务或取得 OS root
- 在独立集群完整恢复包含 ownership/ACL 的备份，再以该集群真实非超级用户 app 登录比较计数、逐行哈希、账本、owner/ACL/extension/role/sequence。当前只支持精确既有 app 角色与 app/postgres/pg_database_owner 依赖；未知依赖失败停止，不能静默跳过
- 恢复成功证据含实际 cgroup v1 memory+pids 限额、UID/权限、peak/failcnt；确认通过才清理本次独占临时叶目录，失败目录保留。所有备份/验收记录保留
- 再核对数据库未变化，仅在一个事务里执行原文 0041+账本插入，设置 lock_timeout5秒/statement_timeout60秒；不运行 migrate.ts 的编辑回填
- 检查精确新增账本、布尔 false/NOT NULL、已验证约束、旧行内容/旧账本及计数不变；仅更新 shared schema 记录，保存旧清单，绝不改旧 release 清单
- 原子切 current 到固定 d57，启动 API/Web，核对精确版本健康/UID/实际内存限制/旧8000 listener/原 UID989 egress，写 root-only `/var/lib/aifinance-maintenance/collect-only-upgrade.json`

### Collector

- 单独 nologin `aifinance-collect` 账号，独占 UID/组。只复制 DATABASE_URL 到 root-owned 0440 DB-only 文件；不复制 admin/model/session/image 凭据，不新建 DB 用户/密码
- 固定 d57 源文件 SHA256 与三条 RSS URL，整棵运行目录须 root-owned 只读。不会因 timer 运行而升级代码
- 专用 UID 的 nft 表只允许既有 DB loopback:55432；每次启动前 root 有界解析三固定域名，拒绝非公网地址，绑定固定 hosts+hosts-only NSS，再临时只允许这些 IPv4 的443。采集 UID 禁止 DNS；HTTP 只执行冻结代码里的三固定 feed，现有代码拒绝跨源重定向。HTTPS IP共享不能独立证明域名/路径，主机/路径限制依赖冻结且核验过的应用代码
- 无网络 sleep 探针与所有采集/check/seed 单元使用同 UID、256MiB、Tasks32、120秒、NNP/空capability/只读文件系统；核对实际 `/proc` 和 memory/pids cgroup v1、resolver挂载。只做配置语法检查不算验收
- 首次 seed/run 都创建独占 attempt 记录，任何前次尝试存在即停止；失败后不能无审阅重复采集。首批暂停 API/Web、确认无其它写入，再比较前后快照和 CLI：processed总和≤3，素材/修订增量匹配，jobs/model/editorial/publication/delivery/grouping计数完全不变；不存在的 pgboss 不当作0
- 正常结束还原专用网络至无HTTPS状态，重新启动并检查d57 API/Web；失败停采集、禁timer、撤销专用配置读取/HTTPS，维护停机状态保留给管理员处理
- 首批成功+管理员页面验收后，单独安装/启用每小时 timer。定时执行仍每批≤3、独立UID/DB-only/固定RSS；应用可能并发写入，因此定时结果不会冒称“全表零增量”已再次验收

## 失败边界

任何检查不符即停止。升级中止后 API/Web 可能保持停止，旧8000不动。不要运行旧版本回退、删除文章或重写旧 schema 哈希来“通过检查”。0041事务失败则未切版本；0041已提交而后续失败则保留加性schema/证据，另审恢复方案；采集后尤其不能盲退到无 collect-only 守卫的旧应用。全库恢复涉及丢弃备份后的写入，必须另行确认损失窗口。

这里没有写 native-ready；不宣称常规 deploy、压力测试、重启/故障后恢复已获通过。

## 测试与未验证项

- 本地：typecheck、Web build、19个Web测试、现有部署/隔离回归、新 helper 离线安全测试
- CI：现有完整 backend/Web/Docker 测试；Python3.6.8 实际容器跑两套 helper 测试；新增现有 disposable PG17 service 上的真实 custom-format dump/restore、0041事务中途失败原子回滚、重复迁移拒绝测试
- 本地云机没有 PostgreSQL/server systemd239/cgroupv1，因此不将 fixture/mock 或 Python3.6语法解析冒称真实目标机通过。目标机还必须实际执行 check、受限恢复单元和collector probe/run后审阅证据
