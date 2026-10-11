# 重建 ECS：待审批的部署适配

新增只读现状、同版本 bootstrap 回退和通道审批见
[首次布局适配与接入审批草案](rebuilt-bootstrap-access.md)。现状未满足启用 policy 的条件。

本改动提供代码、夹具和 GitHub CI 验证，不代表目标机已安装或验收。基于
`release/aifinance-preview@14f53d08f35b37f4716009ed1b35f1c2318d5eaf`，复用现有
`package.sh`、受限解包器和构建检查。旧入口及其哈希清单保持不变；新入口使用
`rebuilt-v1`，不回退到旧协议，也不调用旧初始化、采集或运维安装器。

## 已知条件与拒绝条件

用户提供的恢复状态：Ubuntu 24.04，服务为 `aifinance-api.service`、
`aifinance-web.service`，运行用户均为 `aifinance-deploy`；Web/API 仅监听
`127.0.0.1:3000/3001`，数据库仅监听 `127.0.0.1:55432`；当前代码位于
`/opt/aifinance/staging/d57ba047369e666025347719caee1a4c642abe62`。
本次没有连服务器核实这些条件，也没有读取生产数据库或配置中的凭据。

`rebuilt-policy.example.json` 默认 `accepted:false`，未知路径为 null，不能直接启用。
管理员在单独批准的只读核查后填入根所有、不可由应用修改的
`/etc/aifinance-rebuilt.json`。必须确认：

- 真实 Node 可执行文件及 Node 24.11+ 的 24.x 版本。
- 实际的 `current_link` 和 `releases_dir`，不是自动假定旧 `state/current` 存在。
  切换链接必须已存在，最初指向上述 staging 目录；发布目录必须已存在。
  两者位于 `/opt/aifinance` 内，无符号链接祖先且不互相包含。
- 两个 systemd unit 的六个属性与 policy 精确一致：User、WorkingDirectory、
  ExecStart、FragmentPath、DropInPaths、EnvironmentFiles。不要把凭据放在命令行或
  policy；凭据仍留在原有配置中，不读取其内容。
- WorkingDirectory 必须为已批准切换链接本身或其 `apps/web` 子目录。
  若真实 unit 直接绑定 staging，入口明确拒绝，不猜测、改写或迁移 unit。
  管理员还须确认启动命令实际从切换链接加载代码，并把 `AIHOT_RELEASE` 设为该版本完整 SHA；
  `/api/health` 未返回对应 SHA 时发布失败，不能以 `dev` 或旧 SHA 放行。
- 当前版本已有正确 `RELEASE_SHA`、构建产物、依赖和 `schema.sha256`。
  policy 的 `schema_sha256` 是这个迁移文件清单本身的 SHA256；代码还逐项核对真实 SQL 内容。
  数据库地址和结构与清单一致由管理员另行验收。`verified:true` 是验收声明，
  **不是入口查询数据库所得的证据**。入口不连接数据库、不迁移、不恢复数据。
- `incoming`、发布目录、切换链接父目录以及 `state/rebuilt` 的写权限需预先确认；
  `state/rebuilt` 必须为部署用户所有、0700 的实目录。入口不创建这些基础目录。
- root 所有且不可由应用改写的入口与解包器安装在 `/opt/aifinance/bin`。
  仅允许精确的两个服务联合 restart 命令；权限缺失时失败，不自行改 sudoers。
  不增加 root SSH、任意 systemctl、任意 shell、SFTP 或端口转发。

已知运行用户和部署用户相同。本适配没有偷偷改用户；因此状态目录、发布文件与应用
**不是不同 UID 的强隔离边界**。状态文件用于恢复任务上下文，不能声称是防应用篡改的审计账本。
如要求抵抗被攻陷应用，须单独批准运行身份/权限分离，不能仅靠本补丁。

## 固定协议与失败恢复

单独批准安装后的强制命令入口为 `python3 -I -B /opt/aifinance/bin/rebuilt-gateway.py`，
仍需 `restrict,command=...` 公钥约束及 root 所有的 SSH 配置；本补丁不写 authorized_keys。
只接受以下完整格式，SHA 为 40 位小写十六进制，摘要为 64 位，操作 ID 为 32 位：

| 命令（均以前缀 `rebuilt-v1 ` 开始） | 行为 |
| --- | --- |
| `verify` | 只确认协议与专用账户，不宣称布局已验收 |
| `inspect` / `status` | 返回当前 SHA 和最近操作回执，不导出环境或 unit 命令内容 |
| `status ID` | 查询持久操作回执；回执与当前版本分别返回 |
| `upload SHA DIGEST` | 有界上传；同一 SHA 仅接受相同内容，不覆盖不同包 |
| `deploy SHA DIGEST ID` | 校验、解包、切换、健康检查；失败恢复前一版本 |
| `rollback SHA ID` | 仅切到已存在且结构一致的版本，不恢复数据库 |
| `resume ID` | 从已有回执续作，无需再构建、传包或依赖原云任务存活 |
| `logs api` / `logs web` | 最近 15 分钟、最多 50 条日志的时间与级别元数据 |

进程间 flock 覆盖上传与发布；写回执、切换链接用原子替换并 fsync。
先记录 `prepared → switching → checking`，再变更服务；失败进入
`rolling_back → rolled_back` 或 `recovery_required`。不同 ID 不能抢占未完成操作。
成功请求重复提交会重新检查当前 SHA 和健康状态，但不再次重启。
同一 ID 的参数不能更改，已被后续版本替代的成功请求不会重新发布旧代码。
健康失败后 `rolled_back` 仍以非零退出，不把回滚成功伪装成部署成功。

云任务或 SSH 响应丢失时，先用 `status` 找到 ID，再 `status ID` / `resume ID`。
切换后、回执完成前中断可恢复；回滚中断可继续回滚。
解包中断、目录已落盘但摘要回执未落盘、路径改变或回滚健康失败等不确定状态会失败关闭，
保留证据供审核；**不能保证任意断电点都自动恢复，也不能手工删回执后盲重试**。
重试失败上传应复用原制品；GitHub 选“重跑失败作业”可复用成功 build 的制品。
重新构建同一 SHA 不保证 tar 字节相同，冲突会拒绝，不能覆盖旧包。
新 workflow 不提供分离的 stage 按钮，避免后续再次构建产生不同制品；不能把“重跑所有作业”当作可靠续作。

状态在服务器持久保存，不依赖 ChatGPT 云任务磁盘或个人电脑。查询输出有界，历史回执
不会自动删除；达到磁盘限额时失败。上线需另行确定保留期限和有审计的清理方式。

日志不返回 MESSAGE、命令行、任意字段或任意服务。正则脱敏不能保证未知格式的密钥不泄漏，
所以首版只提供时间和级别。以当前账户已有 journal 可见性读取，不使用 sudo、不加 journal 组；
空结果不能证明没有日志。需要错误正文时，应另审查固定错误码接口，而不是开放任意日志读取。

## 一次性接入：不默认新增 ECS

先选一种现有条件能够支持的通道，本次没有创建或测试任何一种：

1. **现有云管理通道**：若已具备云助手/受控执行代理，验证它能限制到这一实例、
   `aifinance-deploy` 与固定命令，再接入上述协议。可不新增 SSH 入站和第二台 ECS。
   对应 API 身份、命令约束和 CI 传输适配尚未实现/验收，不能把任意 root 命令 API 当成等价方案。
   官方 RAM 支持实例/Command ID/用户限制，但 InvokeCommand 的 Launcher 等可变输入
   尚无已验证的服务端限制；固定 Command ID 本身不能当作固定入口边界。详见新审批草案。
2. **受限 SSH**：复用已有受控私网通道或经确认的固定来源，仅允许该来源到 TCP 22；
   凭据只在受审批的 GitHub Environment 安全配置，核验重建后的主机指纹。
   当前 YAML 实现这一协议，但默认 GitHub runner 不因此获得网络通路。
   不假设 ChatGPT/GitHub 默认固定出口，不开放 `0.0.0.0/0`，不要求聊天粘贴私钥。

`.github/workflows/deploy-rebuilt.yml` 只有手动入口，没有 push 自动执行；与旧流程共享并发组。
保持 Environment 审批、发布分支限制、完整 SHA 和严格主机指纹检查。
含 SSH 凭据的 job 不 checkout/执行上传代码；构建和测试在无 SSH 凭据的 job 内完成。
操作 ID 由调用方为一次发布明确指定并保存，重试沿用。旧部署入口不会自动兼容新服务器。

上线前需分别批准：推送/PR 与 workflow 启用；通道、凭据与指纹配置；目标只读核查；
入口/policy/目录的安装；任何实际必要的 unit、身份、sudo 或网络变更；首次发布及回滚演练。
新机若不满足切换布局，先形成具体变更 diff，再审批，不能自动迁移真实布局。
仅代码已推送至草稿 PR #4 并运行 Check；未执行服务器或云权限配置。

## 本地验证

`npm run test:rebuilt` 使用临时目录、合成包、真实受限解包器和 mock 服务/HTTP/journal；
不访问 ECS、systemd 或数据库。覆盖并发、重试、恢复、摘要/结构校验、旧版回滚、
失败关闭及日志泄密哨兵。原 `test:deploy` 保留，用于旧方案回归；它的部分历史夹具假定 umask 022。
生产布局、目标 Node/依赖兼容性、API SHA、实际防火墙、journal 可见性、权限及传输通道仍待验收。

### 本次云端核查结果

- `npm run test:rebuilt`：31 项通过（含第二轮边界复查回归）。
- `(umask 022; npm run test:deploy)`：通过；解包器历史套件有 1 项跳过。
  默认 umask 077 下历史首次安装夹具因目录遍历权限假设失败，仅调整测试进程 umask 后通过。
- `npm run test:preview`：5 项通过；`npm run typecheck` 通过。
- `npm run build -w @aihot/web` 通过；前端测试 19 项通过。
- 临时 PostgreSQL 17 空库 `aifinance_rebuilt_ci`（本地 55490）迁移、topics seed、
  本地 Web/API（33300/33301）烟雾检查通过。临时服务与数据库已停止、数据目录已清理。
- 初始禁用模型配置下基线与改动版均有相同 27 项模型桩失败。后续已修复测试隔离：
  仅测试进程清除继承供应商凭据、启用本地模型桩，并在 TCP 层拒绝非回环目标，
  覆盖重定向与子 Node 进程；保留关闭安全阀的负向测试。完整本地后端为 171/171，
  生产服务及 workflow 默认模型开关仍关闭。详细证据见 rebuilt-ecs-validation.md。
- YAML 解析、内嵌 shell 的 `bash -n`、Python 语法和 `git diff --check` 通过。
- GitHub Check 在 `3f7bef78b03eaf45a05c50a3c011f0b5221e2b1d` 的 check/docker/python36
  全部通过；未做目标机连接、生产数据库测试、真实发布或断电演练。

### 第二轮入口复查

已修正非对象健康 JSON 和子进程超时未转成受控失败、恢复时损坏的新版本阻止旧版回滚、
悬空状态链接被当作不存在、锁文件类型/硬链接/权限检查不足等问题。
增加切换前检查当前链接、迁移目录/构建入口链接越界检查、成功重试的结构复验、实际 UID/effective UID 核验。
SIGTERM/SIGHUP 保留恢复状态并清理正在等待的子进程；新/恢复发布在锁内检查固定服务是否仍有 systemd job，
有作业则拒绝，不取消或并发发起重启。日志查询从 journal 侧只请求元数据字段。
同 UID 应用篡改与管理员并行修改不能被普通 flock 彻底隔离，仍需实际权限验收。

回滚证据是临时目录中的真实链接切换/受限解包，加 mock systemd/HTTP/journal 的隔离测试。
**未在真实 ECS 完成部署、重启或回滚演练**；不能将本地回归结果表述为线上回滚已验证。
