# 同版本 bootstrap：一次性审批与回退

> 2026-10-13 更新：现场报告同版本 bootstrap 已验收，随后增加 root 管理的
> 90-home-compat.conf，固定只读代理连接也已验收；本轮未连接 ECS。备案仍 pending，
> 网站保持 localhost。下文原安装/接入状态是历史记录，当前本地发布准备、兼容性和
> 待批准步骤以 [受限发布准备](rebuilt-ecs-deploy.md) 为准；新代码尚未安装或推送。


**仅代码准备，未执行服务器操作。** 适用实例 `i-2zedybs3fftu1d9vnx39`，
不是部署新版本或接通运维通道。目标只把原版本通过固定链接启动。
需要管理员批准安装下列文件及两个应用重启；通常中断数秒至数十秒，启动异常时
可能持续数分钟，不能保证中断上限。应选维护窗口并保持原管理恢复入口可用。
SSH、防火墙、数据库、Hermes、其他服务、sudoers 和现有凭据都不在本次变更范围。

## 已明确的原配置与精确差异

两 unit 均为 `/etc/systemd/system/aifinance-{api,web}.service`、User=aifinance-deploy，
无现有 DropIn。两者原 WorkingDirectory 均为：

`/opt/aifinance/staging/d57ba047369e666025347719caee1a4c642abe62`

原 ExecStart 分别为 `/usr/local/bin/node --experimental-strip-types apps/api/src/main.ts`
和 `/usr/local/bin/node --experimental-strip-types apps/web/server.ts`。
两者 EnvironmentFile 均为上述 staging 下的 `.env`，由 systemd 加载。
不修改、不复制、不读取 `.env` 正文，脚本仅校验其路径、类型和权限。

新增两个文件：

- `/etc/systemd/system/aifinance-api.service.d/90-rebuilt-bootstrap.conf`
- `/etc/systemd/system/aifinance-web.service.d/90-rebuilt-bootstrap.conf`

两文件内容相同（仓库有 api/web 两份审阅样本）：

```ini
# Same-version bootstrap; inherited ExecStart and EnvironmentFile unchanged.
[Service]
WorkingDirectory=/opt/aifinance/switch/current
```

不重写原 unit，不添加 Environment/ExecStart/User 等覆盖项，原安全设置照旧。
脚本在 daemon-reload 前后及重启后核实六项有效属性：User、WorkingDirectory、
ExecStart、FragmentPath、DropInPaths、EnvironmentFiles，并核对原 unit 文件摘要。
若原有路径在真实 systemd 沙箱中不可达，健康验收失败即回退，不自动放宽沙箱。

## 执行前失败关闭

`check` 只读，不写锁、不建目录、不重启。以下任一条件不满足即退出：

- root 执行；脚本、同目录 gateway/清单以及祖先路径可信，Node 是 root 管理的
  普通文件且版本恰为 v24.21.0；相关目录不能被组/其他用户写入。
- policy 不存在或为明确 accepted=false；switch 与两份 drop-in 的父目录都不存在。
  不覆盖已有链接、drop-in 或其他人的文件。
- 两 unit 的有效配置与上述准确清单一致，无进行中的 systemd job，服务原本健康；
  3000/3001/55432 必须分别仅监听 127.0.0.1。
- RELEASE_SHA 必须严格匹配已知旧提交，不能从目录名推断或自动补写。
  `rebuilt-baseline.sha256` 从该 Git 提交的 398 个 apps/packages/industry/database
  及根 package 文件生成，脚本固定清单摘要并逐文件核对实际内容。
  实际 SQL 集合、字节和 schema.sha256 必须一致；不新增/改写清单。
- 构建入口和 node_modules 存在且不逃逸版本目录。此检查不等于重建并证明所有
  生成产物和第三方依赖字节，也不等于数据库 schema 已被验收。
- `.env` 是原路径普通文件、非软硬链接、root 或部署用户所有，不允许全员读取
  或组/其他用户写入。权限不符合只报告拒绝，不自动改权限或读取内容。

源码或标记不匹配时禁止通过编辑 expected SHA/清单“使检查通过”；应复核原部署
来源。错误输出 JSON 原因码；文件系统失败附 errno/路径，可信性失败附具体路径及
uid/gid/mode。只报告文件元数据，不打印命令输出、unit 内容或秘密。

## 可合并为一次批准的服务器步骤

管理员用**已有获批管理方式**安装当前审阅提交的三个文件；不从服务器拉取并运行
任意分支代码，不要求个人电脑持续在线。文件摘要见
`deploy/native/rebuilt-bootstrap-files.sha256`。先核对摘要，安装前确保目标目录不存在：

| 路径 | 属主 / 权限 | 本阶段用途 |
| --- | --- | --- |
| `/opt/aifinance/bootstrap-v1` | root:root 0755 | 新建的只读工具目录；原 `/opt/aifinance` 必须可信，不递归 chown |
| 上述目录内 `rebuilt-bootstrap.py`、`rebuilt-gateway.py`、`rebuilt-baseline.sha256` | root:root 0644 | Python 显式运行；gateway 仅复用内部检查，不安装 SSH 入口 |
| `/opt/aifinance/switch` | root:root 0755 | 脚本新建；应用无写权限，阶段二再审批是否让部署用户原子换链 |
| `/opt/aifinance/switch/current` | root 创建的符号链接 | 仅指向完整旧 staging；不移动 staging |
| 两个 `.service.d` 目录 / 专属 conf | root:root 0755 / 0644 | 仅新增上述 WorkingDirectory 覆盖 |
| `/var/lib/aifinance-bootstrap` 及 `rebuilt-v1` 子目录 | root:root 0700 | 状态和原 unit 备份，文件 0600；可能含原 unit 内联秘密，禁止上传 |
| `/run/lock/aifinance-rebuilt-bootstrap.lock` | root:root 0600 | 排他锁；拒绝软硬链接/并发操作 |

如这些路径已有内容或所有权不符，停止核查，不覆盖或扩大权限。
管理员按下列顺序执行（此处只是审批对象，并未运行）：

```sh
/usr/bin/python3 -I -B /opt/aifinance/bootstrap-v1/rebuilt-bootstrap.py check
/usr/bin/python3 -I -B /opt/aifinance/bootstrap-v1/rebuilt-bootstrap.py apply
/usr/bin/python3 -I -B /opt/aifinance/bootstrap-v1/rebuilt-bootstrap.py status
```

`apply` 重复全部前置检查、持久记录原状态和 unit 备份，再创建链接/drop-in，
daemon-reload 并检查有效配置，联合重启且**只重启这两个应用服务**。
健康验证检查两服务、Web、API 的 ok/db/release 与回环监听。
首次 apply 有现存回执即拒绝，避免重复重启；status 仅报告状态，不声称新健康检查。
全新无事务且无布局时，status 返回 `not_initialized`、`receipt_exists:false`，
不会写入回执或创建目录。仅已有 STATE 的情形要求它为可信 root-only 0700 空目录。
成功为 `same_version_ready`；不创建 releases/incoming/state/rebuilt，不授予部署 sudo，
不改 EnvironmentFile、不迁移数据、不启用 accepted，也不配置接入身份。

## 回退与异常中断

一般应用/健康失败会自动尝试回退并以失败退出，即使回退成功也不返回发布成功。
回退仅删除本次精确匹配的两份 drop-in，daemon-reload，验证原 unit 没有被别人修改，
再按原配置重启应用。原健康恢复后才移除 switch/current 与空 switch 目录。
原 staging、`.env`、原 unit 和 root-only 证据保留；没有数据库恢复操作。

管理员也可在同一审批范围内手动回退：

```sh
/usr/bin/python3 -I -B /opt/aifinance/bootstrap-v1/rebuilt-bootstrap.py rollback
```

SIGTERM/SIGHUP/中断会尝试恢复；SIGKILL/断电无法执行清理，下次先 status，再 rollback，
不盲重跑 apply。若 systemd 重启作业仍在进行，脚本拒绝竞争，不取消作业。
若原 unit、专属 drop-in 或链接已被外部修改，或存在未知临时文件、恢复健康失败，
保留证据并失败关闭，需要管理员审查；不覆盖别人的改动、不递归删除目录。
初始化证据阶段中断且 state.json 尚不存在时，目标布局尚未修改；管理员检查 root-only
证据后处理，不让脚本猜测。锁只协调本工具，不能阻止管理员并行改服务配置。

## 两阶段健康身份与配置处理

**本阶段保持 dev。** 元数据/源码前置验证与运行时 release 身份是不同证据。
若起初 health.release=dev，切换后必须仍为 dev；不会添加 AIHOT_RELEASE 伪装身份。
若原本已返回已验明基线 SHA，切换后须相同。gateway 的新版本 SHA 健康门禁保持原样，
因此 phase one 成功仍不能启用自动发布。

**阶段二另批：** 实现并测试 root 管理的固定 launcher 或等价方案，按实际切换目录
读取已校验 RELEASE_SHA，确保配置加载不会覆盖身份，再验收 health 返回准确 SHA；
配置 releases/incoming/state/rebuilt、换链权限、最小联合 restart 权限和 policy。
这些都不包含在本次脚本内。

暂时继承旧 `.env` 路径最小且可回退；以后即使链接切到新版本，仍会依赖旧 staging。
不能清理该目录或原 `.env`。若迁至独立 shared 配置，须单独批准管理员在服务器内
安全复制、所有权/权限、精确 EnvironmentFile 差异及重启，验证后再讨论保留策略；
不能通过 Git、制品、聊天或公开路径转移秘密，也不能静默改变环境加载优先级。

本阶段没有建立 SSH/云助手/OIDC 通道。接入身份与云助手参数边界仍按
[接入审批草案](rebuilt-bootstrap-access.md) 单独处理。

## 首次失败报告的复核与更新方式

旧 `invalid_state_or_file` 混淆文件缺失与 JSON 损坏等错误；
`untrusted_policy_or_helper` 不指出具体路径，这是已确认的诊断缺陷。
不是 load/save 初始化死锁：check 不调用 load；首次 apply 创建 STATE/TX 后
保存回执；原子保存不要求 state.json 预先存在。原 c80f386 的完整 CLI 在隔离容器
中可复现首次 status 的笼统错误，但首次 check/apply/status/rollback 全部成功。
服务器 check/apply 的真实拒绝点仍待新错误信息定位，不能声称现场已经修好。

| 新输出 | 含义与处理 |
| --- | --- |
| not_initialized | 无 TX/布局，未开始；check 成功后才可执行已批准 apply |
| receipt_not_initialized | 无事务时请求 rollback；不需要回滚，不创建回执 |
| receipt_missing_in_existing_transaction | TX 存在但回执缺失，可能初始化中断或人为创建；停止并检查 root-only 证据 |
| receipt_invalid_json / invalid_receipt_shape / invalid_receipt | 已有回执损坏或字段不合法，拒绝自动继续 |
| untrusted_path / bootstrap_dependency_untrusted | 具体文件或祖先的属主、权限或类型不符合原规则；不放松校验 |
| filesystem_error / trusted_path_unavailable | 路径及 errno 指向缺失或不可访问对象；不以空文件替代 |

最少现场诊断：新版 status/check 的 JSON 输出，以及所指路径和祖先的文件类型、
uid/gid、八进制权限、是否符号链接（可用 namei/stat 获取）。已有 STATE 是否 0700、
是否有 TX、TX 中的文件名也可报告。不要提供 .env、unit 备份或 state.json 正文。

已安装 c80f386 时，不重建安装目录、不触碰布局或恢复记录：核对旧三文件摘要，
保留旧脚本的 root-only 副本，仅将审阅后的新 rebuilt-bootstrap.py 原子替换到原位置，
保持 root:root 0644。上述仅替换单文件的建议仅适用于历史 c80f386→bc62c6b。2026-10-13 本地准备同时修改
helper，不能套用单文件更新；应先审阅新版安装清单。基线清单未改。新摘要以固定提交的
rebuilt-bootstrap-files.sha256 为准。更新后只先运行 status/check；失败立即停止，
不自动 apply、填 state.json、补 RELEASE_SHA 或改可信策略。
状态确属未初始化且 check 成功时，原已批准的同版本 apply/回退范围仍适用；
修复没有新增服务器、网络、权限或服务变更范围。

旧 17 项测试在临时目录调用函数，替换了 root 可信性和服务查询，没有覆盖完整
CLI 的初始 status/error 输出与真实祖先检查。现在 CI 必跑无网络、无宿主目录挂载
的临时 root 容器测试：真实 UID、属主权限、固定路径、load/save/main/trusted 与
原子文件操作，只有 systemctl/curl/ss/Node 版本命令为替身；不是 ECS 或真实 systemd 验收。
