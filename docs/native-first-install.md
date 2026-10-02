# 原生首次安装：可独立执行的 Node 阶段与后续边界

`deploy/native/first-install.py` 把首次安装拆成独立阶段。**已实现的 apply 只有专用 Node 二进制安装**；它不执行 Node，也不声称 Alibaba Cloud Linux 的 ABI、应用原生模块、数据库、网络隔离或部署已验收。PG 的完整目标事务未知只阻塞 PG 安装及其下游，不再阻塞已审阅的独立 Node 安装。

这是本地开发成果，尚未在服务器运行。旧的 [`prepare-native.py`](native-prepare.md) 仍是全栈只读诊断草案，不应把它的 `--apply` 改成绕过检查。新脚本既不调用该开关，也不扩大 SSH gateway 或 `aifinance-deploy` 的权限。

## 1. 阶段、审批与实际实现

| 阶段 | 精确范围 | 实现状态 / 独立审批 |
|---|---|---|
| 依赖计划 | 输出固定阶段及依赖；不查询主机、不写文件 | `first-install.py plan` 已实现，不需要变更审批 |
| Node check | 固定本地清单、发布签名、哈希、归档结构、目标路径与磁盘余量检查 | `check-node` 已实现，只读；成功仅表示该文件安装的先决条件通过 |
| Node apply | 新建 `/opt/aifinance/runtime/node`，只安装 `bin/node`、`LICENSE`、`INSTALL.json`；必要时创建其 `runtime` 父目录 | `apply-node` 已实现；要单独批准版本/签名/制品哈希/路径/资源边界，不依赖 PG 事务 |
| PostgreSQL 包 | 只允许审阅后的 PG16 或 PG17 **完整确切事务**及必要依赖 | 未实现。目标事务尚未知；不能从四个核心 RPM 猜测闭包 |
| DB、env、units | 新专用 OS 账号、空集群、应用角色、受保护 env、三个新系统级服务 | 未实现；必须单独批准下述有界管理员操作；不生成凭据 |
| 隔离、迁移、验收 | 真实 UID/cgroup 下隔离测试；通过后才运行应用迁移、启动与验收 | 未实现；没有一键绕过、任意 shell hook、测试通过标记或自动 ready 文件 |

审批是用户对明确变更的同意，以及管理员在可信终端执行具体操作。清单、`INSTALL.json`、mock 结果和命令中的 `apply-node` **都不能自行产生用户授权**。不要上传一个写着 `approved=true` 的文件冒充审批。

部署账号继续只拥有已经批准的、固定 API/web 两个服务的 restart 权限。管理员首次安装操作不放进 forced-command gateway，不增加 sudo 子命令，不使用部署账号启动数据库、迁移或 daemon-reload。

## 2. Node 阶段的固定输入

先在已有管理员通道中，将审阅后的脚本放到 `/root/aifinance-first-install.py`。脚本、输入文件和它们的所有祖先目录必须 root 所有、不能被组或其他人写、不能含符号链接。**不要以 root 运行部署账号上传目录里的脚本。** `/opt/aifinance` 必须已经存在且受 root 保护；本工具不创建/接管应用账号或 access bootstrap 根目录。既有 ROOT/runtime 及其祖先还必须允许服务 UID 遍历（other+x）；不合规时拒绝，不擅自 chmod 既有目录。

输入目录固定为 `/root/aifinance-native-inputs`，CLI 不接受其他路径、命令、URL、目的目录或安装参数：

- `node-install.json`：最大 16 KiB，下述精确 schema
- `node-v<具体版本>-linux-x64.tar.xz`：最大 256 MiB，官方版本 URL 的本地副本
- `SHASUMS256.txt`：该版本官方校验和清单，最大 128 KiB
- `SHASUMS256.txt.sig`：其 detached 签名，最大 16 KiB
- `release-keys.gpg`：只读发布公钥环，最大 1 MiB；公钥不是凭据，但真实性仍须独立核对

清单必须恰好含以下字段，拒绝额外字段、重复 JSON key、浮动版本、非官方 URL 与安装钩子。下列占位符不能直接运行，不是实际 pin：

```json
{
  "format": 1,
  "operation": "install-dedicated-node-runtime",
  "node_version": "24.<minor>.<patch>",
  "node_url": "https://nodejs.org/dist/v24.<minor>.<patch>/node-v24.<minor>.<patch>-linux-x64.tar.xz",
  "archive_sha256": "<64 lowercase hex>",
  "shasums_sha256": "<64 lowercase hex>",
  "signature_sha256": "<64 lowercase hex>",
  "keyring_sha256": "<64 lowercase hex>",
  "signer_fingerprint": "<40 or 64 uppercase hex>"
}
```

只接受 Node 24 稳定版且 minor >= 11，不接受其他 major 或带前导零的版本。审阅人须通过独立可信的 Node 发布渠道核对当前有效发布者的完整公钥指纹、未撤销状态、具体版本以及清单 SHA256。攻击者同时提供的公钥、签名和哈希不能证明发布者身份。工具不下载、不导入全局公钥、不联系 keyserver、不自动更新发行密钥。

目标必须已有 root 保护的 `/usr/bin/gpgv`。它是唯一允许的子进程，参数固定为本目录的公钥环、签名与清单，15 秒超时、空 stdin、不输出原始 stderr、仅继承固定 PATH/HOME/locale。脚本要求 `VALIDSIG` 匹配审阅的完整指纹，拒绝验证器报告的坏签名/过期/撤销状态及弱摘要，清单中目标文件必须唯一且与制品 pin 相符。注意：[GnuPG 官方说明](https://www.gnupg.org/documentation/manuals/gnupg/gpgv.html) 明确 gpgv 把本地 keyring 中的公钥视为可信，不自行检查公钥过期或撤销；该状态列表不是自动密钥生命周期验证。因此当前有效发布者及未撤销状态必须纳入独立官方审阅，不能仅凭 gpgv 成功得出此结论。gpgv 缺失或无法验证就停止；**不自动安装 GnuPG**。若目标没有它，先另行审阅该依赖的最小安装事务，不可改成“只核对哈希就放行”。

## 3. Node check/apply 的管理员命令

以下命令中的 `REVIEWED_PLAN_SHA256` 表示审阅人独立确认的真实 64 位小写 SHA256；不能使用占位符或从未核验的上传文本直接复制作为信任依据。

```sh
env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ LANG=C LC_ALL=C \
  /usr/bin/python3 -I -B /root/aifinance-first-install.py plan

env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ LANG=C LC_ALL=C \
  /usr/bin/python3 -I -B /root/aifinance-first-install.py check-node \
  --plan-sha256 REVIEWED_PLAN_SHA256
```

在获得 **“批准将此确切官方 Node 制品安装到新的固定专用路径”** 的同意后，由管理员执行：

```sh
env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ LANG=C LC_ALL=C \
  /usr/bin/python3 -I -B /root/aifinance-first-install.py apply-node \
  --plan-sha256 REVIEWED_PLAN_SHA256
```

check 和 apply 都重新检查字节、签名及路径；apply 在首次写入前再次检查目标。apply 还要求 root UID/GID 和受保护脚本。系统 Linux/x86_64、Python 3.6.8+ 是安装器条件，**不等于 Node 能在目标 ABI 上运行**。安装路径所在文件系统须至少有 `MAX_NODE + 1 GiB` 可用空间；swap 不参与任何内存预算。

返回码：成功 `0`；输入、签名、归档、权限、资源或写入失败 `1`；CLI 用法错误 `2`。成功的 check 仍给出 `explicit_administrator_approval_still_required=true` 和 `ready_for_deploy=false`。检查无写入；它不调用 Node、包管理器、systemctl、数据库、网络或 shell，不读取 env、凭据和服务日志。

### 安装行为与失败恢复

- 归档只复制该版本目录下的两个普通文件：`bin/node` 与 `LICENSE`。不安装 npm、npx、corepack、系统软链接或归档中其他文件，不调用 tar 的 extract/extractall
- 遍历时限制 50,000 项、512 MiB 总展开大小；拒绝绝对路径、`..`、硬链接、特殊文件、重复路径和不合规目标成员。不提取归档里的符号链接。Node 必须是 x86_64 ELF，仍不执行它
- 在 tarfile 解码 PAX/GNU 元数据正文前，限制每项 64 KiB、累计 16 MiB，拒绝 sparse；CLI 在解析前设置 128 MiB 地址空间、CPU 软/硬上限 30/35 秒、257 MiB 单文件上限和零 core dump，并保留更严格的继承限制。资源耗尽时停止，不自动提额重试
- 对 root 保护输入使用 `O_NOFOLLOW` 和打开后元数据复核；哈希与读取归档使用同一文件句柄。目标目录和文件采用独占创建，不能覆盖一个完整、空、部分或符号链接形式的既有安装
- 新 `node` 目录起初是 `0700`，复制/同步完成及写入普通安装回执后才变为 `0755`。新 runtime 父目录显式设为 `0755`，避免管理员 `umask 077` 阻断应用访问。所有新文件由 root 建立；实际 Node 路径为 `/opt/aifinance/runtime/node/bin/node`
- `INSTALL.json` 只记录安装字节身份，并明确 `runtime_or_ABI_accepted=false`、`ready_for_deploy=false`。它不是 `native-ready` 或 schema 验收记录
- 中途写入或资源失败会保留新建的私有部分目录，下一次运行拒绝自动接管；管理员先检查再决定修复。没有递归删除、安装回滚或重试覆盖，也不停止任何服务。既有数据库、schema 记录、其他 runtime 和旧 8000 服务不动

此阶段没有启动服务，因此它失败时没有“本次新建 preview 服务”需要停止。后续首次启动阶段另按第 6 节处理。

## 4. PG 精确事务：只阻塞 PG 安装

要准备的下一份审批材料必须包含：

1. root 只读诊断中的已安装包、模块、仓库、现有数据库/服务/目录及候选包；缺失或查询失败记作 unknown，不当作未安装
2. 选定 PG16 **或** PG17，官方来源、公钥完整指纹、全部包确切 NEVRA/哈希；四个核心 RPM 不是完整闭包
3. 目标解析产生的**完整事务**：新增、升级、替换、移除、冲突、脚本副作用、服务自动启动、总下载与磁盘增量、仓库/模块变更；不省略“已经装好”的依赖
4. 明确允许列表只有已审阅新增的 PG 和必要依赖。任何系统 Node/Python、glibc/libstdc++、旧 PG、旧服务依赖的替换/移除/升级都停止；不得 `--nodeps`、全局 upgrade、改 `$releasever` 或临时在 ECS 编译
5. 如果元数据不足，只请求一项限定仓库、时间与磁盘的刷新/仓库配置审批。之后再次输出完整事务再批准安装，不能把只读诊断授权沿用到安装

**当前不知道确切目标事务，所以这里故意没有可复制的 `dnf install` 猜测命令。** 后续包安装器只接受该事务的固定允许列表并复核预览一致，不接受任意命令字符串或安装 hook。此关卡不会撤销已经批准并完成的独立 Node 文件安装。

## 5. DB/env/units：给管理员的有界操作合同，尚无 apply 实现

下表是下一阶段必须实现并审阅的固定操作序列，不是当前脚本支持的命令。签名工具、包闭包、应用发布制品及最终 unit/launcher 都审阅后，才能填入确切命令并批量申请这项首次初始化审批。**不能把表格当作现在已经可运行的一键安装器。**

| 顺序 | 唯一允许的新对象/操作 | fail-closed 前提 |
|---|---|---|
| 1 | 新非登录 OS 账号/组 `aifinance-pg`；保留现有 `aifinance` 应用账号和 `aifinance-deploy` restart-only 权限 | 账号/组/目录名已有或身份不符即停止；不修改既有账户，不新增 sudo |
| 2 | `/var/lib/aifinance-preview/postgresql` 新空集群与私有 socket 目录；只调用审阅的 `/usr/pgsql-16/bin/initdb` **或** `/usr/pgsql-17/bin/initdb`，以 `aifinance-pg` 运行 | 确切包事务已验收、目录全新、所有者/父目录/容量合规、55432 空闲。不能接受任意 binary/数据目录，也不复用默认集群 |
| 3 | root 审阅的固定 `postgresql.conf`/`pg_hba.conf`、专用 DB 系统 unit | `listen_addresses='127.0.0.1'`、`port=55432`、`shared_buffers=64MB`、`max_connections=16`；只允许独立 app DB/role 的 loopback SCRAM 与私有 socket 的指定管理员 peer，其他连接拒绝；无 trust、无公网监听 |
| 4 | 数据库与 LOGIN 角色均为 `aifinance_preview`，角色 NOSUPERUSER/NOCREATEDB/NOCREATEROLE/NOREPLICATION；新 DB 安装 `pg_trgm` | 用专用管理员连接执行固定 SQL；不得读/改旧库。超级用户连接串不交给应用 |
| 5 | 已由用户/管理员安全建立的 `/etc/aifinance-preview.env`，仅 root 和必要 API 账号可读 | 管理员通过安全交互设置新独立密码及会话密钥；本仓库不生成/接收/回显/保存真实凭据。不能用聊天、命令行参数、日志或 GitHub Secrets 传输这些凭据 |
| 6 | root 保护的 launcher 与 API/web/DB 三个系统级 unit；不 enable worker | 固定服务名 `aifinance-preview-api.service`、`aifinance-preview-web.service`、`aifinance-preview-db.service`；API/web `User=aifinance`、DB `User=aifinance-pg`，只使用审阅脚本和固定 runtime |
| 7 | 审阅的 release 制品就位、只读初次选择与身份核对 | 发布 SHA、字节哈希、schema 指纹、权限/路径与实际制品相符。root **绝不执行上传的 JS/TS/native module**；也不能作为 deploy 用户去执行它们 |

账号创建、initdb、角色/库/env 配置、unit 文件写入及 systemd daemon-reload/start 都必须出现在该次明确审批范围。审批应附确切命令/SQL/unit 内容和新对象清单；不能仅批一份“准备成功”记录。现有资源身份不明确就暂停，不能靠强制覆盖消除冲突。

三个系统级服务使用 cgroup v1 可核验的 `MemoryLimit`：API `320M`、web `256M`、DB `256M`，总候选上限 `832 MiB`；不是 2 GiB 主机的容量保证。保留 NoNewPrivileges、只读系统路径、loopback 出入站边界及工作目录限制；不因旧内核不支持而删除限制。web 不应得到数据库、管理员或会话密钥。所有采集、模型、飞书、IndexNow 开关关闭，无 worker，原 8000/Python 服务保持原状。

## 6. 真实隔离、迁移与首次启动验收

此阶段必须在目标机取证，mock 不可替代：

1. 首先只运行受 root 保护、固定内容的隔离测试程序，以实际应用 UID、最终系统级 unit 隔离属性和实际 cgroup 测出外网连接被拒绝，loopback DB/API 通路有效；检查真实 memory controller 与限制值。不能只看 unit 文本或 systemd version。即使 BPF 配置存在也不等于过滤生效
2. 隔离未通过就停止。只有通过后，才允许首次执行上传的应用依赖/原生模块和 `scripts/migrate.ts`；必须以专用 `aifinance` UID，在已验证隔离的系统级一次性迁移服务内执行。root 不运行 Node 版本命令、`require()`、npm、JS 或 TS；deploy 账号也不执行上传应用代码
3. 迁移授权只覆盖这个新空库及审阅的 schema。核对数据库/角色/扩展/迁移列表，0039 影响必须审阅；不是空库就另行审阅备份恢复和迁移范围。应用角色保持最小权限
4. 启动固定 API/web/DB，核对 3100/3101/55432 仅 loopback、API 健康接口的正确 release SHA、web 可用、空/未发布内容不可见、安全阀关闭、无 worker；重查 8000 健康及其他业务
5. 实际验证 Node/native modules ABI、内存峰值/OOM/重启行为及可用余量；不能把 glibc 2.32 或 ELF 头视作依赖可加载证明。失败时应重建可信目标匹配制品，不能盲升系统库
6. 管理员记录真实测试证据、时刻、版本与制品身份，复核通过后才写受保护的实际 schema 指纹与 `native-ready`。当前 Node 安装器永远不写它们

后续首次启动失败时，只由管理员停止**本次确实新建且已经启动的**三个 preview 服务，准确集合最多为 API/web/DB；不是统一停止未知旧服务。保留 DB/data、发布制品与诊断记录，停止重试并汇报。没有旧版本时不能声称“已回滚”，不能自动删库、恢复数据、改 gateway/sudo 或触碰 8000。受限部署账号没有 stop 权限，不应为首次安装临时扩权。

## 7. 本地测试

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/tests/first-install-check.py
```

测试在临时目录对真实归档字节、哈希、创建/权限/失败保留行为进行验证；仅模拟 root 元数据与 GPGV 子进程。覆盖签名失败/超时/错误签名者、精确命令白名单、弱摘要、未知字段/命令注入、已有安装与竞争创建、归档遍历/硬链接/重复成员、超大 PAX/GNU 元数据、只读 check、写入中途失败和数据保留。不会实际执行 root 系统变更、官方 Node 或应用代码。另行核验真实制品时，应记录官方签名/哈希证据及有限资源下的归档测试，不把这些结果扩张为目标验收。这些测试不证明真实发布签名、目标安装、ABI、PG 闭包、隔离或上线成功。
