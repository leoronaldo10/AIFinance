# 首次布局适配与接入审批草案

> 2026-10-13 更新：现场报告同版本 bootstrap 已验收，随后增加 root 管理的
> 90-home-compat.conf，固定只读代理连接也已验收；本轮未连接 ECS。备案仍 pending，
> 网站保持 localhost。下文原安装/接入状态是历史记录，当前本地发布准备、兼容性和
> 待批准步骤以 [受限发布准备](rebuilt-ecs-deploy.md) 为准；新代码尚未安装或推送。


截至 2026-10-11。仅方案，不是安装脚本；本轮没有连接 ECS、设置 RAM、
创建凭据、开端口、重启服务或启用 policy。无需新增第二台 ECS。

## 用户提供的现状与待核实项

现状报告位于服务器 `/opt/aifinance/recovery/DEPLOY_ACCESS_INVENTORY.md`，
不是此前的 `/var/backups` 路径。本助手未直接读取服务器文件。
实例 ID 已补齐为 `i-2zedybs3fftu1d9vnx39`。两个服务均以 `aifinance-deploy`
运行，WorkingDirectory 为 `/opt/aifinance/staging/d57ba047369e666025347719caee1a4c642abe62`。
API ExecStart 为 `/usr/local/bin/node --experimental-strip-types apps/api/src/main.ts`，
web 为 `/usr/local/bin/node --experimental-strip-types apps/web/server.ts`。
二者均由 systemd 的 EnvironmentFile 加载该 staging 下的 `.env`，不是 Node
`--env-file`。这更正了上一报告“无 EnvironmentFile”的信息；不读取配置正文。
unit 位于 `/etc/systemd/system`，无 DropIn；Node v24.21.0；staging 属部署用户。
RELEASE_SHA 和 schema.sha256 存在，但其值仍须前置校验，不能从文件名推断。
releases/current 不存在，health 为 ok=true、db=ok、release=dev。

## A. 代码布局 bootstrap：精确最小方案

见 [同版本 bootstrap 执行与回退清单](rebuilt-bootstrap-runbook.md) 及
`deploy/native/rebuilt-bootstrap.py`。本轮只准备脚本并做夹具测试，没有执行服务器操作。

两份 drop-in 都仅增加 WorkingDirectory=/opt/aifinance/switch/current，
继承原相对 ExecStart、固定 EnvironmentFile 路径及其余安全设置。
不复制 `.env`，不修改 staging，不启用 policy，不引入 launcher，不改数据库。
脚本先核对标记、SQL 与可信运行源码清单，再让同一版本经链接启动；健康响应
继续保持 dev。本阶段成功不等于后续 SHA 发布门禁已验收。

发生失败时删除本次专属 drop-in、daemon-reload、重启原服务；原健康恢复后
才移除新链接。原 unit 被外部修改或 systemd job 仍在进行时停止，保留恢复证据。
具体目录权限、重启中断、安装文件清单、阶段二要求在 runbook 中列明。

## B. 接入身份权限：两条候选通道都尚未接通

### 云助手 + GitHub OIDC：有潜力免 SSH，但固定命令边界仍有缺口

官方 [RAM 示例](https://help.aliyun.com/en/ecs/user-guide/use-ram-to-implement-permission-control)
允许 `ecs:InvokeCommand` 同时限定 command 与 instance 资源。
[执行用户限制](https://www.alibabacloud.com/help/en/ecs/user-guide/run-cloud-assistant-commands-as-a-regular-user)
支持 `StringEquals: ecs:CommandRunAs = aifinance-deploy`。应使用单个 cn-beijing
实例 ARN 和单个管理员建立的命令 ARN，不给 RunCommand/CreateCommand/
ModifyCommand/DeleteCommand/ModifyInvocationAttribute 或泛化 RAM 管理权限。
必须核实该身份全部有效策略，不能靠一条窄 Allow 抵消其他宽 Allow。
已核实 InstanceId 为 `i-2zedybs3fftu1d9vnx39`；RAM 使用该实例 ID，不能使用主机名。

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
| A1 前置检查 | 已有 ExecStart/EnvironmentFile 由脚本比对；只读校验标记/源码/结构清单/权限；不读秘密正文 |
| A2 同版本布局 | 仅 root-owned switch/current 与恢复记录；不补写版本标记，不创建发布目录；保留 staging |
| A3 启动切换 | 两个仅改 WorkingDirectory 的 drop-in；批准应用重启及失败恢复原配置；本阶段无 launcher |
| A4 后续发布门禁 | 另批动态 SHA 身份、配置稳定路径、发布目录及最小重启权限，完整验收后才 accepted |
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
