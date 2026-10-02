> 当前阶段（2026-10-02）：目标已完成 Node24.21.0 与四个 PG17.11 RPM 的实际安装。本文保留早期 check-only 设计说明；当前剩余执行计划见 [第一次个人预览](native-first-preview.md)，不要重复安装，也不要将下方历史未知项视为当前永久阻断。

# 原生运行时准备：只读检查草案

`deploy/native/prepare-native.py` 是 **check-only 的准备草案，不是已完成的安装器**。这是本轮草案的实现边界，并非原生部署永久不可行；独立 Node 的真实 check/apply 已在 [`first-install.py`](../deploy/native/first-install.py) 实现，见[最小首次安装阶段](native-first-install.md)；PG 事务未知仅阻塞 PG 阶段。获授权后应按下文三个阶段继续。当前所有检查都返回 `ready_for_apply=false` 和 `ready_for_deploy=false`；`--apply` 始终在任何写入前拒绝。即使本地制品校验全部通过，也不会安装软件、创建账号、写 unit/env、初始化数据库、迁移、启动服务或生成验收标记。

本次只在开发工作区做代码和模拟测试。没有连接目标服务器，没有下载/安装目标运行时，没有生成或处理凭据，也没有修改受限 SSH gateway、sudoers 或 GitHub Secrets。部署账号目前的 `verify` / `inspect` 和固定两个应用服务的 restart 权限保持原范围；不能通过给 gateway 增加 prepare/shell/任意 sudo 来补齐安装权限。

## 下一步：三个有界审批阶段

1. **一次 root 只读诊断**：在已有管理员终端运行独立的 [`inspect-prerequisites.sh`](../deploy/native/inspect-prerequisites.sh)，返回一份带固定小标题的标准输出。只读采样已获授权；无需另加 sudo/gateway 权限。当前 checker 的基本快照不足以替代此 root 调查。原非 root `inspect` 中 PG 查询不可用，不能推断未安装或不存在候选包。
2. **精确依赖事务与安装**：先审阅诊断；仅在缓存不足时，另行批准一次限定仓库、时长和磁盘使用的元数据刷新，或确切 PGDG 仓库配置。取得并批准完整事务之后，才实施专用 Node24 和 PG16/17 安装。不得把诊断授权当作安装授权。
3. **独立数据库与首次启动**：批准专用账号/空集群/角色/安全凭据、迁移、三个新服务和目标验收。通过实际网络隔离与资源验收后，再开通代码发布；用户已有管理员 SSH 的本地转发可以另行授权作为私有访问方式，不更改 forced-command 部署密钥。

将审阅后的单个 shell 文件放到已有可信管理员终端的 `/root/inspect-prerequisites.sh`，运行：

```sh
env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ LANG=C LC_ALL=C /bin/bash --noprofile --norc /root/inspect-prerequisites.sh
```

已有完整主机采样时，只补 DNF 缺口，不重复系统/内存/端口信息。使用审阅后的 v2 文件的新路径，不覆盖旧已发布文件：

```sh
env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ LANG=C LC_ALL=C /bin/bash --noprofile --norc /root/inspect-prerequisites-v2.sh --dnf-only
```

文件没有其他脚本依赖，使用系统 `/usr/bin/python3`（兼容 3.6）过滤 DNF 输出；仅接受无参数的完整诊断或固定 `--dnf-only`。每个命令 12 秒超时、标准输出 8 KiB 上限；DNF stderr 同样有 8 KiB 上限，只返回固定错误类别，不回显原文。DNF stdout 只保留 repository ID、固定 PG 包版本/架构/仓库 ID、PG 模块 stream/状态，丢弃仓库名称、URL、描述及其他任意文本。临时 DNF log/persist 目录为私有目录，完成清理。非零、缺项、截断都表示 UNKNOWN，不能当作不存在。返回一份输出即可，勿附 env、密钥或服务日志。采样覆盖以下字段：

| 字段 | 固定只读来源与判断 |
|---|---|
| OS / kernel / ABI | `/etc/os-release` 的 ID/VERSION_ID、`uname -r`、glibc 版本；系统 libstdc++ 的 GLIBCXX 版本字符串（排序后末5项），仅作 ABI 线索。候选 Node/原生模块所需 GLIBC/GLIBCXX 要从**已固定并核验制品**的 ELF 版本要求另行对比；制品尚缺时明确填 unknown |
| 已装包 | root `rpm -q` 固定集合：glibc、libstdc++、nodejs、postgresql/server/contrib/libs、postgresql16 与 postgresql17 对应四包；输出固定包名的已装版本或查询状态。未找到某固定名字不等于没有别的安装方式 |
| PG 模块、候选包、仓库 | root `dnf -C --noplugins` 的固定 repolist、list --available、module list 和 repoquery；另以 rpm -q 记录 dnf/python3-dnf/libdnf 版本。保留发行版 dnf.conf、reposdir、varsdir、releasever、module_platform_id 和缓存路径，不改成 /dev/null。只关闭本次查询的可选 DNS 密钥检查；日志/persistdir 指向临时私有目录。repoquery 覆盖系统 PG 与 PGDG16/17 四包，保留各项最新 name/version-release/arch、repository ID，关闭模块过滤。list 使用正常模块过滤作交叉核对；两者都只查已有缓存。禁用插件、临时 persistdir 缺少系统 module-failsafe 状态，意味着这些结果不能替代安装事务解析 |
| cgroup / kernel 过滤能力 | `findmnt` 的 cgroup 类型与挂载、`/proc/cgroups` 的 memory controller 存在状态；只读 kernel config 中 CONFIG_MEMCG、CONFIG_BPF、CONFIG_BPF_SYSCALL、CONFIG_CGROUP_BPF，配置不可读就填 unknown。版本/配置存在不证明 app unit 上过滤有效 |
| 资源、监听、服务 | MemTotal/MemAvailable/SwapTotal/SwapFree、`/opt` 磁盘空闲；8000/3100/3101/55432 的监听地址类别；固定 preview 三个 unit 的 LoadState/ActiveState/MemoryLimit/MemoryCurrent。目录所有者/验收标记元数据由既有 `inspect` 补充；不要读取 env 或标记内私密信息 |

旧诊断的三个 DNF 命令同时 exit 1、stdout 为空，**不能据此认定无缓存或无 PG 候选**。[上游 DNF 4.7.0](https://github.com/rpm-software-management/dnf/blob/4.7.0/dnf/cli/cli.py#L842-L846) 在加载显式 `--config` 前要求 `os.path.isfile`；`/dev/null` 是字符设备，会产生“config file does not exist”并在子命令之前退出。这是与现场现象吻合的确定上游机制，目标发行版是否同一路径尚未取得原 stderr 证据；不把它写成已核实目标根因。修正版去掉该覆盖和多余硬编码默认路径，并分类报告 `config_path_not_regular`、`config_error`、`cache_unavailable`、`releasever_unknown`、`module_platform_unknown`、`unsupported_command_or_option` 等错误。未知错误也不回显敏感内容。

[DNF 官方 cache-only 说明](https://dnf.readthedocs.io/en/stable/command_ref.html#options) 表明 `-C` 使用系统缓存且不刷新，即便缓存过期。此查询不安装、下载包、增加/切换仓库、启用模块或更改服务器配置；包管理器本身可能仍使用常规锁或派生缓存，不能把它表述为底层文件系统绝对零写入。DNF 内部缓存实现的实际行为未在目标机测试。

这一步仅使用已获授权的 root **只读采样**，不包含升级、仓库变更、网络配置、启动服务或开放端口。`dnf -C` 无缓存时不得自动重试联网；将缺失项合并成第二阶段的一次有界审批请求。若 root 诊断直接证明现成包和隔离条件足够，跳过不必要的仓库刷新，直接准备精确事务审阅。

## 1. 先检查，保留现有业务

目标 profile 是 Alibaba Cloud Linux `3.2104`、x86_64、glibc `2.32`、systemd `239`、cgroup v1、Python `3.6.8+`。已有 Node 22 不满足本仓库要求。系统自带 Node/Python 和已有 8000 服务不动；不得全局 `dnf upgrade`、改系统 `$releasever`、替换 libc/libstdc++ 或在小型服务器上临时编译。

只读运行（不需要 root；不可读取的项目会阻塞后续判断）：

```sh
python3 -B deploy/native/prepare-native.py
```

- 固定读取 OS、内存、磁盘、cgroup 与 TCP 监听元数据；只查询固定 systemd 服务的 LoadState 和固定运行时路径的版本
- 不读取 env、密钥、服务日志、进程完整命令行；不调用包管理器、网络、sudo 或 shell
- 8000 的监听仅记录并保留；3100、3101、55432 中任何一个被占用就停止，不能杀进程或改用他人的端口
- PostgreSQL 只探测 `/usr/pgsql-16`、`/usr/pgsql-17` 的固定二进制与 `pg_trgm.control`；**探测不到不代表没有安装 PostgreSQL**，也不代表现有数据库可被接管
- 发现已有 preview unit/runtime，或状态不可验证，应人工核对之前的操作；不会覆盖、收编或清理
- 固定只读命令有 5 秒超时；原始 stderr 不进入报告

退出码：`2` 表示检查完成但准备受阻；`3` 表示 `--apply` 被拒绝；`1` 表示输入不可读或不合规。参数语法错误也是 `2`，须结合输出识别。当前没有表示“可部署”的成功退出码。

内存检查要求至少约 1 GiB MemAvailable、4 GiB 磁盘余量，只是重新审查前的下限。候选预算是 API `MemoryLimit=320M`、web `256M`、独立数据库 `256M`，合计 832 MiB。2 GiB 机器、约 1.03 GiB 可用内存和 4 GiB swap **不构成容量保证**；还要为旧业务、连接、页缓存和迁移峰值留余量。不要把 swap 加到可用 RAM 预算里。目标数据会变化，每次安装/首次启动前都须重查。

## 2. 本地制品清单只校验字节，不证明兼容

检查器可选接收人工审阅过的 JSON 清单和独立确认的清单 SHA256：

```sh
python3 -B deploy/native/prepare-native.py \
  --plan /root/aifinance-native-inputs/reviewed-plan.json \
  --plan-sha256 <人工核验的64位小写SHA256>
```

占位符不是可用的 pin。清单与制品必须已经存在，文件和所有祖先目录由 root 持有、不可被其他账号写入、不能是符号链接。检查器不会下载、解包或执行这些制品。不要直接运行来自部署账号可写目录的管理员脚本。

清单格式严格限制为以下五个字段，不接受重复或额外字段：

- `format`：整数 `1`
- `node_version`：具体 `24.x.y`，`x >= 11`；必须是完整稳定版本号
- `node`：只有 `path`、`url`、`sha256` 三个字符串字段；URL 必须是该确切版本的 `https://nodejs.org/dist/v<version>/node-v<version>-linux-x64.tar.xz`
- `postgresql_major`：整数 `16` 或 `17`
- `postgresql_rpms`：四个制品对象，每个只有 `path`、`url`、`sha256`；只描述同一完整版本/build 的 `postgresql<major>`、`-libs`、`-server`、`-contrib`。URL 必须是 `https://download.postgresql.org/pub/repos/yum/<major>/redhat/rhel-8-x86_64/<确切RPM文件名>`，且文件名与本地路径一致

每个 SHA256 都是 64 位小写十六进制，单个输入最大 512 MiB；清单最大 64 KiB。无 `latest`、URL 参数、凭据、镜像替换、任意安装参数或脚本钩子。真实制品应先通过可信官方发布渠道及签名核验，审阅人再固定 URL/version/hash。**用户提供的哈希本身不证明发布者可信。** 检查结果明确保留 `trusted_vendor_signatures_checked=false` 和 `dependency_closure_verified=false`，因为本脚本没有实现这两项。

该清单只列四个 PGDG 核心包，不声称它们是完整事务，更不能据此执行 `rpm --nodeps`。缺少可信制品、哈希不符、混合版本、目录不可信，均直接拒绝。

## 3. PostgreSQL 依赖事务是未解决的关键关卡

[阿里云官方 PostgreSQL 文档](https://www.alibabacloud.com/help/en/ecs/user-guide/build-a-primary-or-secondary-postgresql-architecture) 给出了 Alibaba Cloud Linux 3 使用 EL8 PGDG 的路径；当前示例是 PostgreSQL 18，并在 PGDG 仓库文件内固定 EL8 路径。这是调查 PGDG 的依据，**不是 PG16/17 在这台旧版本机器上可安装的证明**，也不是本 2 GiB 单机预览的安装配方。

实现任何 apply 前，须在经授权的目标管理员通道里完成并审阅：

1. 确认所有已装 PostgreSQL 包、其他集群、服务与数据目录的真实状态；保留现状，不接管默认集群
2. 固定可信源、签名密钥指纹及具体包版本。仅允许经审阅的独立 PGDG EL8 仓库配置；不得修改系统 releasever、切换系统发行版或默认模块来碰运气
3. 先取得 **完整依赖解析/事务预览**，列出新增、升级、替换、移除、冲突、磁盘增量、包脚本/service 副作用。缓存不足或解析失败时报告未知，不自动刷新仓库或降级绕过
4. 必须证明事务不会移除/替换现有业务依赖、默认 Node/Python、系统关键库或旧 PostgreSQL。任何不可解释的系统更新、跨发行版依赖或自动服务启动都要停止另行设计
5. 人工批准确切事务和所需变更后，才可另行开发/审阅安装实现。当前脚本没有调用 `dnf --assumeno`，没有把未经核验的命令冒充可执行事务

如需联网刷新元数据或添加仓库，那是另一个有写入/网络影响的管理员准备步骤，不能放进“只读检查”偷偷执行。不要照抄教程里的可变 `latest` RPM、HTTP 下载、默认服务初始化或全网监听设置。

## 4. 尚未实现的专用运行时/数据库契约

以下是后续实现和验收的边界，**本脚本没有执行它们**：

- Node 安装在 `/opt/aifinance/runtime/node/bin/node`，精确 pin 为 Node 24.11+ 的 24.x；由 root 保护。不得链接/覆盖系统默认 Node，也不得引用 `/root/.local/bin`
- PostgreSQL 使用经事务审查通过的 16 或 17，最终方案复用已由官方RPM创建的 `postgres` UID/GID26、独立空目录 `/var/lib/pgsql/aifinance-preview` 和 `aifinance-preview-db.service`；不能复用旧集群或默认数据库服务。当前DB unit/initdb及首次迁移实现已在本地待审文件中，见新的首次预览计划；尚未获准或在目标执行
- 只监听 `127.0.0.1:55432`，数据库和非超级用户应用角色均为 `aifinance_preview`，使用全新的独立凭据和 SCRAM 认证；不允许 public/trust HBA 条目。应用角色不具有超级用户、创建角色/库或复制权限；不把管理连接串交给应用
- 预览数据库必须实际安装并测试 `pg_trgm`；存在 control 文件只证明候选文件存在。建议首次小负载试验用 `shared_buffers=64MB`、`max_connections=16`，仍需验证连接池及迁移峰值
- 新凭据只能在管理员受保护的本地流程里建立；不要发到聊天、仓库、Repository Secrets 或日志。环境文件只给需要它的 API 账号读取；web 不接收数据库或管理密钥
- API/web/DB 系统级服务使用可在 cgroup v1 上核验的 `MemoryLimit`，保留隔离控制；不启动 worker，所有采集/模型/飞书/IndexNow 外联开关保持关闭
- 应用 launcher、release 脚本和新的 `extract-release.py` 必须一起审阅并安装在 root 保护的 bin 目录；不能仅更新 release 脚本而遗漏提取器

## 5. 实际验收后才能创建就绪记录

仅有版本输出、校验和、`systemd-analyze verify` 成功、unit 中写了限制，或 mock 测试通过，都不能创建 `schema.sha256` / `native-ready`。

后续经批准的首次启动验收至少包括：

1. 在专用空库执行获批迁移并核对实际 schema、`pg_trgm`、角色权限与数据库身份。0039 对旧内容有撤下效果，不能对未知/现存数据库自动跑迁移；备份恢复方案要先审阅
2. 在目标环境验证专用 Node、实际应用依赖和原生模块可加载。glibc 版本合适不等于 glibc/libstdc++/原生模块 ABI 已通过。若失败，停止并重建可信目标匹配制品，不能在 ECS 上盲升系统库
3. 用实际服务账号、systemd 系统级 unit 与对应 cgroup，验证 API/web 出站访问确实被禁止，而 loopback DB/API 通信可用。**cgroup v1 或旧内核可能不支持所需 BPF 过滤；没有实际拒绝证据就停止，不删除隔离规则或改写验收标记**
4. 确认 3100/3101/55432 均只有预期 loopback 监听，8000 旧服务仍健康；核对真实 cgroup memory limit 和压力下峰值、OOM/重启行为
5. 确认健康 API 返回正确 release SHA、web 可用、空/未发布内容不公开、外联安全阀关闭，没有 worker；验证私有访问方式，不能临时开公网端口作为捷径
6. 完成后才由管理员记录验收时间、目标版本、制品身份和真实测试证据，再写入受保护的 schema 指纹与 native-ready。两个标记不应由部署账号写入，也不应由“check”自动生成

首次启动失败：只停止本次新建的 preview API/web/DB 服务，保留新数据库和诊断证据，交由管理员确认下一步；没有旧版时不能声称已回滚。不得删除数据、自动恢复数据库或触碰 8000/其他服务。已有版本升级失败时的代码回滚也不等于数据库回滚。

## 开发验证

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/tests/prepare-native-check.py
PYTHONDONTWRITEBYTECODE=1 python3 scripts/tests/inspect-prerequisites-check.py
```

测试覆盖非写入检查、所有输入通过仍拒绝 apply、检查先于制品验证、哈希/目录/URL/混合版本边界、固定子进程及干净环境、端口冲突、资源不足与状态未知。它们使用模拟进程/元数据和工作区临时文件，**不证明服务器兼容性、PG 安装成功、出站隔离或上线完成**。
