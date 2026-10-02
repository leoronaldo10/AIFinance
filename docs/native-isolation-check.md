# cgroup v1 原生预览：一次有界的真实隔离验收

适用背景：用户提供的目标是 Alibaba Cloud Linux 3.2104 U13 / 5.10.134-19.3.al8 / x86_64，systemd 239，**只有 cgroup v1**，memory 等 controller 已启用，firewalld 正运行，nft 1.0.4、iptables 1.8.5（nf_tables）。约 1.04 GiB MemAvailable 是当时快照，执行前必须重查。本文件和探针只在本地准备；**没有执行任何目标机操作，也没有完成目标验收**。

## 1. 结论与最小可行方案

不能把现有 unit 的 `IPAddressDeny=any` 当作这台机器的外联边界。上游 [systemd v239 的 bpf_firewall_supported()](https://github.com/systemd/systemd/blob/v239/src/core/bpf-firewall.c#L588-L619) 在 systemd 自身 cgroup controller 不是 unified 时直接返回不支持；内核开启 BPF/CGROUP_BPF 不改变该判断。发行版 backport 必须另行核对，不能推定已修复。[v239 手册](https://github.com/systemd/systemd/blob/v239/man/systemd.resource-control.xml#L501-L504) 也说明不支持时这些设置不生效。

保持主机 v1、不重启、不切换 cgroup、不动 firewalld：增加一个**只匹配已核验的 aifinance 数字 UID** 的独立 nft `inet` OUTPUT 表，允许目标地址为 loopback，拒绝该 UID 的其他 IPv4/IPv6 发包。其他 UID 在该表不受限制，仍按原 firewalld 规则处理。API/web/迁移使用该唯一 UID；不要把部署账号、DB 账号或旧 8000 服务加进此范围。

这是一项新的安全网络配置，必须先获得明确审批。先做本文的短时探针，验证后再审阅持久化保护、启动依赖和真实应用验收。**临时测试成功不允许直接启用应用**；独立 Node 文件安装可按 [首次安装阶段](native-first-install.md) 继续，不必等 PG 包事务。

## 2. 审批清单和停止条件

管理员在现有可信 root 终端执行，部署账号和 forced-command gateway 不增加权限。将以下完整变更一次呈交审批，不能把只读诊断授权当作批准：

- 新建 root 所有、所有祖先不可被非 root 写入的 `/usr/local/libexec/aifinance-isolation-probe.py`（0644），内容是审阅后的 [固定探针](../deploy/native/isolation-probe.py)，记录 SHA256；不执行上传目录中的脚本。不得覆盖已有同名文件
- 新建 `/run/aifinance-isolation-check`（root:root 0700），存放本次 nft 文件和短小证据；不得复用不明旧目录。系统 Python 和上述脚本都须来自已信任来源；不运行 Node、npm、JS/TS 或应用原生模块
- 临时在 **lo** 增加恰好 `192.0.2.254/32`、`2001:db8:ffff::254/128` 两个文档用地址，测试结束逐个撤回。它们不是外网服务，不更改默认路由、转发、DNS、sysctl、接口现有地址或 firewalld
- 启动本文固定名称的短时 system 级探针服务：root 固定监听器、root 对照、实际 `aifinance` UID 的前后对照。每次只测 4 个固定地址的 TCP 48173；无 DNS、代理、HTTP、凭据或用户数据，客户端不发送应用负载，监听器只回固定测试字符串
- 增加一个新 nft `inet aifinance_preview_probe` 表，规则如下；只影响经核验的 app UID。测试结束只删除这个表，**此前先停本次探针**。不 flush ruleset、不修改 firewalld 表、不 reload/restart firewalld、不更改安全组/SSH/8000
- 单次服务 MemoryLimit 64 MiB、TasksMax 16、CPUQuota 10%、RuntimeMaxSec 190 秒、停止宽限 5 秒；客户端正常只需数秒。用同一固定探针串行复测候选 API 320 MiB 和 web 256 MiB 的内核限制值，不预分配这些上限、不故意触发 OOM、不并行运行应用。DB 256 MiB 的实际账号/最终 unit 必须在 DB 阶段另验

执行前：确认 `aifinance` 已存在、UID 非 0 且独占；检查同 UID 的所有进程及 8000 监听者的 UID。旧服务共用该 UID、身份不清、存在应用进程，均停止，不能覆盖/停掉它们来“腾位置”。所有测试服务名、nft 表、临时目录、两个测试地址和 TCP 48173 都必须不存在/未占用；查询失败不是不存在。目标地址若用于现有实验网络也停止。记录原 8000 的 PID/UID/监听地址及管理员已知只读健康检查结果，不猜 URL 或更改业务。

`ip`、`nft`、systemd-run、Python 缺失或受阻就停止；本流程不安装软件。IPv6 被禁用/不能添加地址时不能把 ENETUNREACH 当作拦截成功，也不自动更改 sysctl。另行确定是否批准针对服务禁用 AF_INET6，或者批准修复测试条件。

## 3. 为什么使用这两个测试地址

仅连接一个不通的公网地址，无法区分“规则生效”和“本来就没网”。这里把两个**非 loopback 地址值**暂时放在 lo 上，由可信监听器提供确定可达的目标，同时保留 `127.0.0.1` 和 `::1` 正对照。不依赖公网或 IPv6 默认路由，不联系第三方，也不创建 namespace/veth 或公网端口规则。

这会真实经过本机的 IPv4/IPv6 OUTPUT hook，验证数字 UID 和目的地址匹配。它不是公网物理链路测试；规则按目的地址匹配，**不能改为 `oifname lo accept`**，否则这两个反例也会被放过。验收需要相同 app UID 的前测全部成功、加规则后 loopback 成功/非 loopback 失败、每个协议拒绝计数增加、root 对照仍全部成功。单看失败、errno、静态规则、配置项或脚本退出 0，都不算通过。

若另有已授权、确定可达的真实外部双栈测试端点，可另加数值 IP 的同样正负对照，但不能向未知地址/第三方发送用户信息，不能替换以上确定性证据。本固定脚本不接收任意地址、端口、命令或 URL。

## 4. 管理员命令顺序（需要上述审批后才能执行）

以下是审阅用命令，不是自动安装脚本；同名对象存在、检查失败、任一步不符都停止。先在可信管理员终端以 root 设置 `PATH=/usr/sbin:/usr/bin:/sbin:/bin`、`LC_ALL=C`、`umask 077`，确认实际工具路径。将已审阅脚本独占复制到批准路径，不从应用 release 自动加载。

### 4.1 只读基线与新增测试对象

```sh
id aifinance
ps -eo uid,pid,comm
ss -lntp
findmnt -n -t cgroup,cgroup2 -o TARGET,FSTYPE,OPTIONS
cat /proc/cgroups
cat /proc/meminfo
nft list tables
ip -4 address show
ip -6 address show
ip -4 route show table all
ip -6 route show table all
systemctl show firewalld.service -p ActiveState -p SubState
```

人工核对全部前提后，再创建本次对象：

```sh
mkdir -m 0700 /run/aifinance-isolation-check
APP_UID=$(id -u aifinance)
# 人工核对 APP_UID 是上一步的专用非 0 数字 UID；不允许留占位值
ip address add 192.0.2.254/32 dev lo
ip -6 address add 2001:db8:ffff::254/128 dev lo
```

成功添加第一地址、第二步失败时，只删除已成功新增的那个地址。不要删预先存在的对象。IPv6 地址须完成准备（无 tentative/dadfailed），再起监听器。

### 4.2 固定服务属性及可信监听器

在同一 root bash 会话定义公共属性；下列数组只由审阅人固定编写，不接收上传配置：

```bash
probe_props=(
  -p MemoryAccounting=yes -p MemoryLimit=64M -p TasksMax=16 -p CPUQuota=10%
  -p RuntimeMaxSec=190 -p TimeoutStopSec=5 -p KillMode=control-group
  -p Restart=no -p NoNewPrivileges=yes -p 'CapabilityBoundingSet='
  -p 'AmbientCapabilities=' -p PrivateTmp=yes -p ProtectSystem=strict
  -p ProtectHome=yes -p 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6'
  -p LimitNOFILE=64 -p LimitCORE=0 -p UMask=0077
)
systemd-run --unit=aifinance-isolation-listener "${probe_props[@]}" \
  -p User=root -p Group=root /usr/bin/python3 -I -B \
  /usr/local/libexec/aifinance-isolation-probe.py serve
journalctl -u aifinance-isolation-listener --no-pager -n 10
```

须看到 `listeners_ready=true` 且四个地址均由该服务 PID 监听。监听器运行最多 180 秒或 64 次连接；**过期就停止本轮，不把后续连接失败当通过**。需要重做时清理本轮后重新执行前后对照，不无限延长。脚本拒绝 root 运行 app 模式，拒绝无 memory v1 cgroup 或内核限制不符；普通用户不能启动监听模式。

### 4.3 加规则前实际 app UID 正对照

```bash
systemd-run --unit=aifinance-isolation-before --wait --pipe \
  "${probe_props[@]}" -p User=aifinance -p Group=aifinance \
  /usr/bin/python3 -I -B /usr/local/libexec/aifinance-isolation-probe.py baseline
```

四项都必须 `connected=true, token_ok=true`；打印自身 PID/UID、真实 memory cgroup、`memory.limit_in_bytes=67108864`。任一失败即本轮 inconclusive，先清理，不加“放行 firewalld”的补丁。这个前测只执行可信固定 Python，不执行应用代码。

### 4.4 添加只限该 UID 的短时 nft 表

核对 APP_UID 后，在本次私有目录创建如下文件。独立表名须已确认不存在；禁止向未知已有表追加或替换：

```bash
cat > /run/aifinance-isolation-check/probe.nft <<EOF
create table inet aifinance_preview_probe {
  chain app_output {
    type filter hook output priority -10; policy accept;
    meta skuid $APP_UID ip daddr 127.0.0.0/8 counter accept comment "app-loopback-v4"
    meta skuid $APP_UID ip6 daddr ::1 counter accept comment "app-loopback-v6"
    meta skuid $APP_UID meta nfproto ipv4 counter reject with icmp type admin-prohibited comment "app-deny-v4"
    meta skuid $APP_UID meta nfproto ipv6 counter reject with icmpv6 type admin-prohibited comment "app-deny-v6"
  }
}
EOF
nft --check --file /run/aifinance-isolation-check/probe.nft
nft --file /run/aifinance-isolation-check/probe.nft
nft -a list table inet aifinance_preview_probe
```

不要加 `ct state established accept` 到 UID 拒绝前，否则规则上线前的外部连接可能保留。此表的 accept 只结束本链，仍要经过后续 base chain；不会绕过 firewalld 的限制。reject 会终止匹配包。`--check` 只做目标解析/校验，不代表过滤已生效；实际 nft 应用是独立原子批次，`create table` 在同名表出现时应失败，不能改成合并已有表；不允许 `flush ruleset`。

### 4.5 拦截与不影响其他 UID 的对照

```bash
systemd-run --unit=aifinance-isolation-after --wait --pipe \
  "${probe_props[@]}" -p User=aifinance -p Group=aifinance \
  /usr/bin/python3 -I -B /usr/local/libexec/aifinance-isolation-probe.py guarded
nft -a list table inet aifinance_preview_probe
systemd-run --unit=aifinance-isolation-control --wait --pipe \
  "${probe_props[@]}" -p User=root -p Group=root \
  /usr/bin/python3 -I -B /usr/local/libexec/aifinance-isolation-probe.py control
```

必须同时满足：

1. app 的 `127.0.0.1`、`::1` 连接/固定回复成功；两个文档地址连接失败
2. `app-deny-v4`、`app-deny-v6` 计数相较前测各增加；UID 没有其他进程/并发探针。所有失败都没有命中该规则、只有超时或无路由，不算成功
3. root 对照四项均成功，监听器未退出；firewalld 状态未变；旧 8000 的原监听进程、只读健康检查保持正常
4. 保存本次确切规则（含数字 UID）、前后计数、探针输出、服务实际属性和内核 memory 文件；不要把环境、密码、应用 env 或用户数据放入证据

然后串行重复 guarded，在每个新服务命令里将唯一的 `MemoryLimit=64M` 改为 `320M` / `256M`，对应加 `--memory-limit-mib 320` / `256`，固定 unit 名分别 `aifinance-isolation-api-budget`、`aifinance-isolation-web-budget`。要求内核文件分别为 `335544320`、`268435456` 字节，并保存各自实际 PID/controller 路径。只设置上限，不分配该数值内存。总时间超出监听器窗口就停止、清理并另开一轮，不把 root 对照或内存证据省略。

## 5. 内存、权限与通过范围

[systemd v239 cgroup.c](https://github.com/systemd/systemd/blob/v239/src/core/cgroup.c#L824-L856) 的 legacy 分支写 `memory.limit_in_bytes`；因此选择 `MemoryLimit`，不用只有 unit 文本的 MemoryMax/MemorySwapMax 宣称保障。探针核对本进程的 v1 controller、实际成员 PID 与内核限制值，也记录 usage/max_usage/failcnt；未读到精确值就失败。**这证明内核该 cgroup 的限制已配置，不等于证明压力下的 OOM/重启行为**。

`memory.limit_in_bytes` 不是 memory+swap 总限额。探针另外记录 `memory.memsw.*` 是否存在及其值，不承诺 systemd 239 在 v1 上通过 MemorySwapMax 限制 swap。依据 [内核 v1 memory 文档](https://docs.kernel.org/admin-guide/cgroup-v1/memory.html)，memsw 是独立边界。若需要“不使用 swap/精确内存加 swap 硬上限”，另审阅每个新服务 cgroup 的固定 memsw 配置，不执行全局 swapoff，也不把交换空间算作可用容量。当前约 1.04 GiB 可用内存下，候选三个服务上限共 832 MiB 很紧；须复核峰值和预留，串行初始化，不在 ECS 编译。

最终 API/web/迁移 unit 至少核对：实际 User/Group、空 CapabilityBoundingSet/AmbientCapabilities、NoNewPrivileges、限制地址族、无外部继承 socket/套接字激活、只读系统路径与批准的数据目录。确认 `/proc/PID/status` 中 UID、NoNewPrivs=1、CapEff=0；不能仅看模板。探针身份属性、最终服务身份属性以及同 UID 的 nft 规则应一致。缺少属性或 manager 警告忽略时停止，不能删掉保护再继续。

允许整个 loopback 与现有 IPAddressAllow=localhost 的意图一致，但**不是对任意敌意代码的完整隔离**：本机代理、DNS 转发、邮件 relay、可调用外部服务的本地 HTTP 服务、AF_UNIX socket 都可能代表它外联。确认该 UID 无权访问这些 relay 或敏感 socket；如存在风险，另审阅只允许 DB 55432/API 3101 与必要已建立 loopback 回包的更窄规则、文件/socket 权限或 network namespace 方案。没有这项核对，不能声称“应用绝无外联能力”。DB 使用独立 UID，不被本探针表覆盖；DB 的 loopback 监听、角色和权限需另验。

## 6. 结束、失败恢复与之后真正部署

本轮结束或失败，先保存本次输出、journal 和服务状态等证据，再停止**本次确实创建的**探针 unit；它们均为 transient、Restart=no、KillMode=control-group。不要用通配符停止服务：

```sh
# 只列出本次成功创建的名字；未创建的名称不作为“需要回滚的旧服务”
systemctl stop aifinance-isolation-listener.service \
  aifinance-isolation-before.service aifinance-isolation-after.service \
  aifinance-isolation-control.service
# 若本轮创建了 api-budget / web-budget，单独停止这两个精确 unit
# 确認本轮服务均无进程；这里只运行过可信探针，没有启动应用
nft delete table inet aifinance_preview_probe
ip address del 192.0.2.254/32 dev lo
ip -6 address del 2001:db8:ffff::254/128 dev lo
```

删除只针对**本次成功创建**的表/地址；已有或不明对象不删。完成后确认该表/两个地址/48173 监听器不存在，firewalld 和旧 8000 正常，保存证据到管理员批准的位置。临时文件和 root 探针脚本由管理员另行处理，不递归删除、不删除 DB/发布物或既有记录。测试规则没有“自动消失后继续跑应用”的定时器；断线时有限时探针自行结束，管理员重连后只清理本次对象。

systemd 239 未使用 `--collect` 时，失败的 transient unit 可能在停止后仍保留。仅对**本次调用确实创建、已停止且当前 ActiveState=failed** 的精确探针 unit，保存完失败证据后执行 `systemctl reset-failed <该精确名称>`。例如，只有确认本次创建的 after 单元符合这些条件时，才执行：

```sh
systemctl show aifinance-isolation-after.service -p LoadState -p ActiveState -p SubState
systemctl reset-failed aifinance-isolation-after.service
systemctl show aifinance-isolation-after.service -p LoadState -p ActiveState -p SubState
```

同名重试前，逐个核对本次拟重用的精确 unit 均已 `LoadState=not-found`；尚未卸载就先查明原因，不覆盖或换名绕过。禁止无名称的全局 `reset-failed`、通配符或操作任何不属于本次调用的旧/无关服务。正常完成且已经卸载的单元无需 reset；查询错误不等于 `not-found`。

后续最小部署顺序是：

1. 审阅正式的同 UID 网络策略（换正式独立表名、固定数字 UID）、root 保护的加载/校验程序和 system 级网络保护 unit，以及 API/web/一次性迁移的启动依赖。**先加载并核验，再允许执行任何上传的应用代码**。不能用可由 deploy 账号伪造的“通过”文件代替
2. 持久规则必须经明确审批；保留 firewalld 的拥有权和原配置，禁止全局规则刷新。先核对目标 firewalld 版本/后端；不能仅凭“nft 后端一般只管理自己表”认定 reload/reboot 无缺口。预览运行时不做 firewall reload/restart；若需要，应先停新预览服务，确认正式 UID 表仍在/恢复且重新通过探针后再启动。重启后的服务顺序和丢规则时 fail-closed 行为必须实际验收
3. 此网络边界与真实 v1 memory 通过后，在同 UID/最终隔离属性的一次性系统服务执行已审阅迁移，随后启动 API/web。最终 DB/API/web 端口必须仅 loopback（55432/3101/3100），无 worker、安全阀全关；不开放公网入口、不触碰 8000
4. 再验最终服务真实 memory/cgroup、权限、loopback DB/API 连通、应用 ABI、发布 SHA、schema、健康与低负载峰值/OOM/重启。出现失败只停本次新建服务并保留数据，不能写 native-ready 或宣称已上线

这里没有产生新的凭据、sudo/gateway 权限、上传执行授权、持久 firewall 配置、应用启动或 `native-ready`。探针输出始终包含 `isolation_accepted=false` 和 `ready_for_deploy=false`；管理员合并完整证据后才决定是否通过本阶段。

## 7. 本地验证及官方依据

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/tests/isolation-probe-check.py
```

本地 10 项测试覆盖：地址/端口固定、前测必须全可达、断网不能成为通过结果、双栈反例与 loopback 正例、TCP 已连上但回复错误不得当作拦截、结果不得自授验收、root 不能冒充 app UID、实际 memory 文件/PID 核对、v2/root cgroup 不能伪装 v1 证据、单批多个就绪连接不得突破 64 次接受上限。网络/内核数据使用明确 mock；**本环境没有 target systemd 239/cgroup v1/nft，不曾运行真实 firewall 或目标机测试**。`nft --check`、真实 cgroup、规则计数和旧 8000 不受影响均仍是目标机待验收项。

补充官方参考：[nft 手册的 skuid/多 base chain/计数器语义](https://netfilter.org/projects/nftables/manpage.html)、[firewalld nft 后端表隔离说明](https://firewalld.org/2018/07/nftables-backend)。当前文档与发行版版本可能不同，实际目标命令解析和行为测试不可省略。
