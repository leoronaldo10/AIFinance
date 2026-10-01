# 原生预览：SSH 排查与 GitHub Actions 发布准备

这是可审阅的方案与模板，不是已配置、已部署的服务。保留 `docker-compose.preview.yml`；没有 Docker 的 ECS 使用另一套 systemd 预览方案，**不能将 Docker internal 网络保证套到 systemd 上**。两种方式不要共用数据库或数据目录。本流程不依赖用户电脑开机，构建在 GitHub Actions，服务由 ECS systemd 运行；云端诊断会话不是持久运维通道。

## 当前事实与上线前阻碍

目标方案面向 Alibaba Cloud Linux 3、x86_64、约 2 GiB 内存的小型 ECS。机器可能已有业务进程、不同版本 Node 和并行进行的手工部署；所有资源、端口、账号及服务状态须在发布前重新取得只读快照，不应在公开仓库记录某一实例的运行细节。

尚需单独授权与落实：

- 出站 SSH 可达性、账号、主机指纹、凭据交付及服务器安全组。不得默认固定云端出口 IP，不得承诺会话保存密钥。不要通过开放全部来源或关闭主机指纹校验解决连通性。
- 独立 `aifinance-deploy` 与运行账号 `aifinance`、路径权限和最小 sudo 权限。不能直接使用 root SSH 或依赖 `/root/.local/bin`。这些模板不创建账号、不写 authorized_keys、不改 sudoers。
- `/usr/local/bin/node` 可被服务账号执行，版本为 Node 24.11+ 的 24.x；系统 Python 3、curl、flock、tar 可用。不要替换现有机器的默认 Node 或机器人的运行环境。
- 独立的本地 PostgreSQL 与 `aifinance_preview` 数据库、独立数据库角色和新凭据；不复用生产数据库和凭据。现存数据与备份/恢复流程尚未确认。
- HTTPS 域名与宿主机反向代理。服务仅占用 loopback 3100/3101，先确认端口空闲；不占用 8000，不重启 Nginx/机器人/其他服务。
- 核实 systemd 的 `IPAddressDeny=any` / `IPAddressAllow=localhost` 在此内核与 cgroup/BPF 上真正生效；不支持时必须停止，不得仅看 unit 解析成功就认定隔离。限制允许 loopback，不能隔离宿主机其他服务；应用仍保留 SSRF 防护，配置仅允许专用 loopback DB。原生模板不等价于完全沙箱。
- 云端构建 runner 与 Alibaba Cloud Linux 的 glibc/libstdc++ 可能不同。打包包括生产依赖及原生模块，不能假设二进制兼容。切换前脚本只检查 Node；不以部署账号执行上传的 JavaScript。原生模块在受限应用服务启动时加载，失败由健康检查触发回滚，仍需目标机启动验收。若失败，另建匹配目标系统的可信构建环境，不在 2GB ECS 上临时编译或盲目升级系统库。

## 只读排查与访问配置

接入初始化、Windows 生成专用密钥和受限 GitHub Environment 设置按[一次性接入说明](access-bootstrap.md)。该流程只准备持续访问，不安装运行时或部署应用。

`deploy/native/inspect.sh` 只读系统、资源、监听端口及指定服务状态，不读取环境文件、私钥或进程完整命令行。先确认目标和授权再通过临时安全 SSH 身份运行；输出仍需视为服务器信息。实际出站 SSH 与登录支持取决于云环境和服务器网络，不能从“已安装 ssh”推断可用。

GitHub Actions 接入必须在受限的 `aifinance-preview` Environment 内配置 Secrets：`AIFINANCE_SSH_HOST`、`AIFINANCE_SSH_PORT`、`AIFINANCE_SSH_KEY`、`AIFINANCE_SSH_KNOWN_HOSTS`。固定账号为 `aifinance-deploy`。私钥不得保存为 Repository Secret。先从可信的阿里云终端核验主机公钥指纹，再填 known_hosts（非默认端口需要 `[host]:port`）。不能仅信任现场 ssh-keyscan 输出，不把密钥粘贴在聊天、仓库或日志中。推荐专用且可吊销的部署凭据；仅允许写 AIFinance incoming/releases 和执行固定服务重启。实际密钥管理机制、轮换与账号建立须单独确认。

工作流临时文件权限 0600，StrictHostKeyChecking 开启、禁用交互密码；结束清理 runner 的临时密钥。此机制不代表平台替用户长期保存 SSH 私钥。必须实际配置并验证 Environment 只允许明确的 `release/aifinance-preview` 分支，并限制该分支的写入者；若设置不可用或无法落实则停止，不退回仓库级私钥。不能仅凭工作流 if 条件声称密钥受保护。

## 文件与发布行为

- `deploy/native/package.sh`：只打包指定的干净提交、构建产物和生产依赖，输出提交 SHA、迁移文件指纹、tar.gz 与 SHA256。拒绝未提交修改；不会把未追踪 `.env` 或 `.data` 打包。
- `deploy/native/run-preview.py`：白名单读取 `/etc/aifinance-preview.env`，丢弃继承环境，强制生产模式、安全预览和关闭外联开关。web 不接收数据库和管理密钥。不会启动 worker。
- 两个 `aifinance-preview-*.service`：仅 API/web；运行账号隔离、只读系统和专用数据写目录，内存上限 384/512 MiB。PostgreSQL 与 OS 另需资源预算；swap 不等于内存容量验证。
- `deploy/native/release.sh`：以部署账号运行，目录锁防并发，校验包与安全解包，核对数据库指纹和 Node 版本，原子切换 current，只重启两个固定服务。API 健康响应必须包含目标 SHA，web 首页必须可访问。
- 新版本不健康时恢复旧链接并再次检查；回滚也失败会非零退出并明确提示人工处理。首次部署没有旧版时不会假称已回滚。没有自动删除旧版本、数据库迁移、数据库恢复、服务安装或重启其他服务。

工作目录预期（需先审批并由管理员配置）：

```text
/opt/aifinance/bin/                  # 经过审阅的 launcher/release 脚本；管理员持有，部署账号不可改
/opt/aifinance/incoming/             # 部署账号上传包
/opt/aifinance/releases/<完整SHA>/    # 部署账号管理；运行账号只读
/opt/aifinance/state/current         # 部署账号可写的状态目录内原子切换软链接
/opt/aifinance/shared/data/          # 运行账号可写，仅预览数据
/opt/aifinance/shared/schema.sha256  # 管理员确认的数据库对应迁移指纹
/opt/aifinance/shared/native-ready   # 管理员完成网络/服务/端口/权限验收的标记
/etc/aifinance-preview.env           # 管理员持有，运行账号只读；使用独立新凭据
```

`native-ready` 是人工验收记录，不是网络隔离的检测器；不能为了通过脚本而直接创建。记录验收时间、系统版本与限制测试结果，环境变化后重新验证。sudo 仅允许非交互执行 `/usr/bin/systemctl restart aifinance-preview-api.service aifinance-preview-web.service`，不要给任意 systemctl、shell 或 sudo 权限。bin、unit、env 和 schema 验收文件不应由部署账号可写。

## 手动工作流与回滚

`.github/workflows/deploy-preview.yml` 手动运行默认 `build`；构建/发布/回滚要求完整 40 位提交 SHA。另有仅可信发布分支 push 触发的 `verify`，只验证接入，不部署：

1. `build`：云端安装、类型检查、安全回归、前端构建与测试，生成可下载 Artifact，不连接服务器。
2. `deploy`：目标提交必须属于可信发布分支历史。无 SSH Secret 的构建 job 产出包；另一个干净 runner 在受限 Environment 中通过 forced-command 上传并发布，不执行包内代码。
3. `verify`：通过受限账号返回固定接入成功标识，无需 Node/PostgreSQL，不调用 sudo 或发布。
4. `rollback`：选服务器上已保留的完整 SHA，不重新构建，只切换兼容数据库的已有代码版本。

当前未提交的改动不会被远端工作流看到；先审阅、获授权后提交/推送，手动 Run workflow 需要工作流位于默认分支；首次接入验证可在明确批准创建可信发布分支后由其 push 触发，无需为验证合并 main。GitHub Actions 整体权限、仓库计划、网络与 Secrets 必须现场确认。并发组防止同一工作流互相打断，服务器锁还覆盖人工调用；另一会话如直接修改服务或目录仍会造成冲突，实际发布前须协调停止手工变更。

## 数据库边界与验收

不在 release 脚本或工作流执行 migrate/seed。初次建库与每次 schema 变化都单独做备份、恢复演练和迁移审批；0039 会撤下旧公开内容，不能自动执行。`shared/schema.sha256` 仅在数据库已完成相应迁移且核实后由管理员维护，不能仅复制文件绕过检查。目标与当前版本的指纹必须一致，确保本流程只做代码切换；需要跨 schema 变更时另行安排维护流程。代码回滚不恢复数据库或业务数据。

当前测试使用假服务和假 HTTP 响应验证控制流，未在 ECS 操作任何服务。仍需真实验证：完整 PostgreSQL 后端测试、迁移/恢复、原生依赖 ABI、systemd/BPF 实际出站阻断、HTTPS、管理员操作和手机预览、内存/磁盘峰值。没有这些结果不能宣布已具备无人值守上线条件。
