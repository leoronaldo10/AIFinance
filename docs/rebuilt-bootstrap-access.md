# 首次布局适配与接入审批草案

截至 2026-10-11。仅方案，不是安装脚本；本轮没有连接 ECS、设置 RAM、
创建凭据、开端口、重启服务或启用 policy。无需新增第二台 ECS。

## 用户提供的现状与待核实项

现状报告位于服务器 `/opt/aifinance/recovery/DEPLOY_ACCESS_INVENTORY.md`，
不是此前的 `/var/backups` 路径。本助手未直接读取服务器文件。
两个服务均以 `aifinance-deploy` 运行，WorkingDirectory 直接指向
`/opt/aifinance/staging/d57ba047369e666025347719caee1a4c642abe62`。
unit 位于 `/etc/systemd/system`，无 DropIn、无 EnvironmentFile；
`/usr/local/bin/node` 为 v24.21.0；staging 属部署用户；releases/current 不存在。
API health 为 ok=true、db=ok、release=dev。

这意味着 gateway 当前必须拒绝发布：没有切换布局，不能证明旧版身份，
也不能用健康接口确认实际运行的 SHA。不能只把 `accepted` 改成 true。
Node 版本满足版本门槛，但文件及祖先目录可信权限仍需验收。

无 EnvironmentFile **不等于无环境配置**。下一次已授权只读核查只需提供：
ExecStart 的可执行路径、参数结构（值脱敏）、是否含 `--env-file`、是否调用
包装器、包装器/程序是否加载 dotenv 或分组 credentials、相关文件路径与权限。
不要输出 `systemctl show Environment`、完整进程环境、配置正文或含秘密的命令行。
还要确认相对配置路径是否依赖旧 WorkingDirectory；新版制品不包含 `.env`。
若需把配置改成稳定外部绝对路径，必须另列具体差异审批，不能顺手复制秘密进制品。

## A. 代码布局 bootstrap：先让原版本通过切换链接运行

1. **留存恢复基线。** 管理员在服务器上以 root-only 权限保存原两个 unit、
   实际配置加载方式和待变更文件的原状态/摘要，位置建议为 recovery 下独立操作目录。
   不上传可能含秘密的备份。保留 staging 代码、原启动方式和已有管理恢复通道；
   不改变数据库、不运行 migrate/seed。
2. **验明旧版。** 核实目录中的真实代码对应 `d57ba047...`，构建产物、依赖、
   `RELEASE_SHA` 和完整 SQL 清单一致。缺少标记时不能仅凭目录名补写；
   先用可信制品/版本证据证明代码，再单独批准补充元数据。
   `schema.sha256` 须按 package.sh 的排序/格式生成并核对全部 SQL；另由管理员
   核实数据库结构与基线一致。磁盘清单不是数据库已迁移的证明。
3. **只新增所需目录。** 建议 `/opt/aifinance/releases`、`incoming`、
   `state/rebuilt`、`switch` 由部署用户拥有；state/rebuilt 为 0700。
   `/opt/aifinance/switch/current` 首先指向原 staging 目录。
   使用独立 switch 父目录可避免让部署用户写 `/opt/aifinance` 本身及 bin。
   所有父目录须无符号链接；`/opt/aifinance/bin`、入口、解包器、policy
   及其祖先保持 root 所有且不可由应用写入。不要对整棵目录递归 chown。
4. **生成两个精确 unit 差异。** 优先每个 unit 新增一个专用 root-owned drop-in，
   WorkingDirectory 改成 switch/current（web 若真实启动需要，可用其 apps/web）。
   ExecStart 必须实际加载该链接下的代码，不能继续含固定 staging 入口。
   如需替换 ExecStart，须显式清空原值并保留已核实的启动参数和配置来源。
   尚缺真实 ExecStart，当前不能给出可直接应用的最终 diff。
5. **版本身份随链接更新。** 如现启动方式不支持，另审查小型 root-owned launcher：
   固定 API/web 两种入口、固定 Node 路径，解析已验明版本目录并读取完整 SHA，
   在加载既有配置后将 `AIHOT_RELEASE` 设为该 SHA，再 exec 对应 Node 入口。
   不接受任意路径、shell 文本或凭据参数；不能把旧 SHA 永久写死进 unit。
   此 launcher 尚未实现；不能声称现有 gateway 会替应用自动设置环境变量。
6. **同版本重启验收。** 单独批准维护窗口后 daemon-reload，并重启这两个服务。
   确认仍是旧 SHA、API ok/db/release 正确、Web 正常、3000/3001/55432 仅回环。
   通过后再把实际六项 unit 属性、路径、清单摘要写入 policy；最后才批准
   accepted=true 与 database.verified=true。首次发布新 SHA 是下一项独立审批。

**回退：** 在启用 policy 前失败，不调用 gateway 发布；保持/恢复 policy 禁用，
仅移除本次新增的 drop-in（或恢复本次备份的原文件），daemon-reload 后按原方式
重启两个服务。原 staging 保留且没有数据库变更，因此可回到原 release=dev 的
已知服务状态；这不算新布局验收成功。新增目录和回执先保留证据，不递归清理。
若已启用 policy 后再撤销布局，先停用接入、禁用 policy，再恢复原 units。
bootstrap 的人工 unit 回退不同于 gateway 对已验收版本的链接回滚。

## B. 接入身份权限：两条候选通道都尚未接通

### 云助手 + GitHub OIDC：有潜力免 SSH，但固定命令边界仍有缺口

官方 [RAM 示例](https://help.aliyun.com/en/ecs/user-guide/use-ram-to-implement-permission-control)
允许 `ecs:InvokeCommand` 同时限定 command 与 instance 资源。
[执行用户限制](https://www.alibabacloud.com/help/en/ecs/user-guide/run-cloud-assistant-commands-as-a-regular-user)
支持 `StringEquals: ecs:CommandRunAs = aifinance-deploy`。应使用单个 cn-beijing
实例 ARN 和单个管理员建立的命令 ARN，不给 RunCommand/CreateCommand/
ModifyCommand/DeleteCommand/ModifyInvocationAttribute 或泛化 RAM 管理权限。
必须核实该身份全部有效策略，不能靠一条窄 Allow 抵消其他宽 Allow。
主机名 `iZ2zedybs3fftu1d9vnx39Z` 不能代替已核实的 ECS InstanceId；二者不可猜测转换。

但 [InvokeCommand API](https://www.alibabacloud.com/help/en/ecs/developer-reference/api-ecs-2014-05-26-invokecommand)
还允许 Launcher、WorkingDir、Parameters、ContainerId/Name、调度等输入；
容器执行会忽略 Username。该 API 未列出 CommandContent 替换字段，
却也未列出可锁死上述参数的 RAM 条件键。
**推论：Command ID + 用户限制尚不足以证明只有固定脚本可执行**，尤其启动器可变。
未实测漏洞，也未声称 RAM 能限制任意请求字段。把请求参数在 workflow 写死，
不能约束已拿到同一 RAM 临时凭据的调用方。

因此直接 OIDC→RAM→InvokeCommand 暂不满足“不可绕开固定入口”的验收条件。
须先取得官方可验证的服务端参数限制，或另批一个不可绕过的可信调用代理：
代理保管 InvokeCommand 权限，调用方仅能请求固定操作；严格拒绝额外参数、
容器、Launcher 覆盖、调度、输出外送等。仅在脚本内降权也不能保护被替换的 Launcher。
不默认新增代理服务器；若现有基础设施没有这类代理，不掩盖其新增维护成本。

[阿里云官方 Action](https://github.com/aliyun/configure-aliyun-credentials-action)
支持 OIDC 换取短期凭据，默认 audience 为 `sts.aliyuncs.com`，无需长期 AK。
待上述边界解决后，RAM 信任须锁定 GitHub issuer、audience、**该仓库及指定
受审批 Environment 的精确 subject**；Environment 限定 release/aifinance-preview，
不能信任所有 GitHub 仓库或普通 PR。第三方 Action 固定完整审查 SHA。
[GitHub OIDC 文档](https://docs.github.com/en/actions/reference/security/oidc)
说明环境型 subject 与分支型 subject 不同，且实际 subject 可能含不可变 ID；
需核实实际非敏感 claims，不能盲抄示例或输出完整 JWT。

与现有 SSH workflow 相比，后续还需另批并实现：仅接入 job 的 id-token:write、
OIDC 信任/角色配置、参数白名单适配、执行 ID 与操作 ID 的对应、轮询与中断续作、
受限结果查询及制品传输。云助手调用不是 SSH stdin，不能直接复用 upload 管道；
若选择受限对象存储，需要另审查固定桶/前缀/对象、摘要、大小和过期策略，
不能允许任意 URL 下载、无限 SendFile 权限或把凭据放进命令参数。
本轮仅文档，没有添加可执行云权限接入。

### SSH 固定入口：已有协议，仍缺可达路径与密钥配置

由管理员一次性安装 root 控制的 authorized_keys/ForceCommand 配置，
限定 aifinance-deploy、固定 gateway、禁用 shell/PTY/转发/SFTP；只能联合重启
两个既定服务的精确 sudo 命令，不能给任意 systemctl/root shell。
密钥通过受审批 GitHub Environment 或已批准安全注入配置，不在聊天传递；
单独核对重建主机指纹。SSH 身份不授予云 API 权限。
现有 UFW 仅允许 100.104.0.0/16 到 22；普通 GitHub runner 和当前云工作区
未证明在该通道中。先核实已有受控来源，不开放全网 SSH，不承诺固定出口。
若已有可达的受控运行器可复用，SSH 的代码改动最少；不存在则仍是阻塞。

## 一次性审批清单与实测边界

| 审批项 | 具体边界 / 完成条件 |
| --- | --- |
| A1 只读补全 | 脱敏 ExecStart、环境加载路径、旧版/结构证据、父目录权限；不读秘密正文 |
| A2 布局准备 | 上述四个子目录、初始链接、基线元数据；保留 staging；不改数据库 |
| A3 启动切换 | 先给两个实际 unit diff 与 launcher diff，再批准重启窗口和人工回退 |
| A4 启用入口 | root 管理代码/policy、精确联合 restart 权限；同版本健康通过后才 accepted |
| B1 通道选择 | 云助手先解决 Launcher/容器等参数边界；SSH 先证实受控来源路径 |
| B2 身份配置 | 精确实例/命令/用户 RAM+OIDC 或固定 SSH 身份；无长期 AK、无聊天私钥、无宽 root |
| B3 接入验收 | 单独批准只读 verify/status；测试错误用户/实例/命令及危险参数被拒；不发布 |
| C 首次发布 | 另批具体 SHA、制品摘要、维护窗口及已验收旧版本回滚；不附带 DB 迁移 |

用户报告没有部署 authorized_keys/ForceCommand/云助手脚本目录。
aliyun.service running 与 AssistDaemon 未激活都不足以断言云助手可用或不可用；
应由已获批身份查询该实例 CloudAssistantStatus/版本，并核实实际调用授权。
官方要求运行前确认 Agent 状态；本次没有调用该 API。

本云环境实测：GitHub push/PR/Check 可用；`aliyun` CLI 未发现，标准 Alibaba
AK/STS/角色/OIDC 环境变量未配置，CLI 配置文件不存在（仅检查存在性，未读取内容）。
这不排除产品侧另有注入机制，但没有证据证明当前会话能获取 GitHub OIDC 或调用 ECS。
OIDC 方案的执行位置应是经审批的 GitHub job，不能把本会话等同该 job。
未做新的 ECS TCP/SSH 检查，也未声称工作区永久常驻或已形成持续运维通道。
