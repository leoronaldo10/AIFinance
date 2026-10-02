# 原生个人预览：待审批 UID 出站保护

仅本地实现和 mock 测试。没有安装、启用、修改目标网络或启动目标应用；不产生 `native-ready`。适用 ALinux 3 / systemd 239 / cgroup v1，不能把 unit 中 `IPAddressDeny=any` 视为有效边界。

## 最小变更和权限

[egress-guard.py](../deploy/native/egress-guard.py) 只允许 `start`、`verify`、`stop` 三个固定操作，全部要求 root。审批后的流程将其安装到固定 `/opt/aifinance/bin/egress-guard.py`，root:root 0644，文件及所有祖先不可被非 root 写入且不能是 symlink。审阅并记录 SHA256 后才安装；不要以 root 从 deploy 可写 release/incoming 中执行代码。系统 Python 与 `/usr/sbin/nft` 也必须是可信 vendor 文件。

[aifinance-preview-egress.service](../deploy/native/aifinance-preview-egress.service) 是 DB/API/web 之外的**第 4 个辅助 unit**，不是额外应用进程。root 运行 oneshot，`RemainAfterExit=yes`，没有后台轮询或自动修复。unit 安装、daemon-reload、是否启用开机启动、实际 start/stop 均须明确审批。它不启动或更改 firewalld，只在 firewalld 已进入启动事务时排在其后。

该 unit 使用 `/run/aifinance-preview-egress`（root:root 0700），其中 root-only receipt 记录数字 UID 和本次随机规则标识，使用文件锁串行化本 helper 操作。`RuntimeDirectoryPreserve=yes` 保留失败后的归属证据；正常重启清空 `/run`，nft 内存规则也需由 guard 重新建立。receipt 是归属线索，**不是内核规则存在的替代证明**。

`start` 使用 `getpwnam('aifinance')` 获取真实非 0 UID，拒绝同 UID 的其他账户；检查 `/proc` 中 real/effective/saved/fs UID，不允许已有该 UID 进程。管理员还必须核对账户用途、8000 旧服务及其他遗留任务，不靠这个扫描替代完整基线。读取失败就停止。`/proc` 扫描不是阻止其他 root 同时启动进程的锁；维护窗口必须停止并禁止并发启动 preview/迁移/同 UID 任务。

唯一新表是 `inet aifinance_preview_egress_v1`，仅一个 OUTPUT base chain，priority -10，policy accept：

- 每条规则都只匹配实际 `aifinance` 数字 UID
- 允许目的地址 `127.0.0.0/8` 和 `::1`，不使用 `oifname lo accept`
- 其余 IPv4 和 IPv6 分别带计数器 reject；不加 established 例外
- 不覆盖 postgres UID 26、部署 UID、root 或其他 UID，不新增账户，不更改 8000/firewalld/iptables/SSH/安全组

先确认新表不存在，再 `nft --check`，最后通过包含 `create table` 的原子批次加载；同名表出现则失败，不合并、不替换、不 flush。四条规则与 JSON 检查均在 helper 中固定生成，CLI 不接受任意 UID、表名、地址、文件路径或命令。`verify` 读取内核表，精确比较链类型/hook/优先级/policy、规则顺序、UID、目的地址、双栈 reject 和本次标识，允许计数器变化；未知/额外对象、规则改动、缺表、UID 改变或查询失败一律拒绝。

## 启动依赖和失败行为

API/web 各有 `BindsTo=aifinance-preview-egress.service` 与 `After=...`，并增加固定：

```ini
ExecStartPre=+/usr/bin/python3 -I -B /opt/aifinance/bin/egress-guard.py verify
```

只这一条可信 Python 检查以 root 执行；主 `ExecStart` 仍以 aifinance 执行，空 `CapabilityBoundingSet`/`AmbientCapabilities`、`NoNewPrivileges=yes`。不给 app UID root nft、AF_NETLINK 或 sudo 权限。上游 [systemd v239 手册](https://github.com/systemd/systemd/blob/v239/man/systemd.service.xml) 已支持 `+`；[execute.c](https://github.com/systemd/systemd/blob/v239/src/core/execute.c) 以该标志跳过此命令的权限和 seccomp 限制。目标发行版的实际执行仍须验收。

首次迁移也须在 root 确认 guard loaded 后，以 aifinance 在有 `BindsTo`/`After` 依赖的固定一次性 unit 运行，并加入相同 root `ExecStartPre`。不以 root 运行迁移或上传 JS。`first-preview` root 流程负责这些操作；不能以 root verify 成功代替后续 unit 的依赖。

正常 systemd stop guard 时，反向 `After` 顺序先停依赖的 API/web，再执行 guard 的 `stop`。删除前再次检查该 UID 无剩余进程，核对 receipt 和精确内核规则，只按本次表的 handle 删除；不删除未知、被修改或替换的表。任何失败保留规则/receipt并要求管理员审查。初次 `ExecStart` 失败时 systemd 不保证调用 `ExecStop`，因此没有危险的 `ExecStopPost` 自动删除；管理员只能在所有本次 app/迁移/探针确已停止后显式调用固定 `stop`。若归属或结构已不一致，helper 拒绝删除，不能以全局 flush 或删 receipt 来“修好”。

**oneshot active 不等于规则持续存在。** 启动前检查能拒绝缺失/失效保护下的新启动；若其他 root 在应用运行中删规则，oneshot 不会察觉、不会自动停止已运行应用。这里只针对可信管理员维护下的个人低负载预览，没有连续监控、对抗 root 的能力或完整强隔离保证。loopback/AF_UNIX 可达的恶意本地代理/relay 仍可能代表它外联；必须核对可达的本地服务，不为本阶段扩账号或宣称绝无外联。

## firewalld reload 的准确范围

firewalld 官方 [nft 后端说明](https://firewalld.org/2018/07/nftables-backend) 的 “Only flush firewalld’s rules” 明确称该后端 reload/restart 仅清理自己的 `firewalld` 表，目的是保留独立自定义表。按该设计，新增的独立 inet 表应保留。

但目标实际 firewalld 版本、`FirewallBackend`、发行版补丁以及其他 root 管理脚本尚未核验；已知 nft 1.0.4 / iptables 1.8.5 nf_tables **不能证明这些条件**。不笼统保证目标 reload/restart/reboot 无缺口，也不修改其配置、`FlushAllOnReload` 或拥有权。预览运行期间不得 reload/restart firewalld/nftables。将来若必须做，先停新预览和迁移，再另行审批操作，核对/恢复本表且重做验收后才启动；本阶段不通过真实 reload 来试探旧站风险。

## 复用现有双栈探针的目标验收

不新增大 checker；继续使用已审阅的 [isolation-probe.py](../deploy/native/isolation-probe.py) 和 [临时隔离验收](native-isolation-check.md) 的全部停止条件、固定地址/端口、资源限制、旧 8000 基线、root 对照与清理规则。正式 guard 的验收顺序：

1. 先停所有 preview/迁移/同 UID 任务；确认正式 guard 表和 receipt 不存在。若旧测试留下对象，先按其归属清理，不直接加载已有表。不得同时保留临时 `aifinance_preview_probe` 表，否则可能把临时表的拦截误当正式 guard 有效
2. 按原文 4.1–4.3 建两个文档测试地址、启动限时 root listener，再以 aifinance 做四地址全部可达的 baseline。等待 baseline 完全结束。任何不可达都 inconclusive，不更改原 firewalld 放行来掩盖问题
3. 原文 4.4 的临时表加载操作改为经审批的 `systemctl start aifinance-preview-egress.service`，接着 root `/usr/bin/python3 -I -B /opt/aifinance/bin/egress-guard.py verify`。核对输出 UID/表/handle 和四条规则，留存双栈 counter 基线。不额外创建临时 probe 表
4. 复用原文 4.5 的 guarded、root control、320/256 MiB 串行探针。正式 guard 注释是随机标识加 `:deny-v4` / `:deny-v6`，比较同一标识的两个计数器增量；两种 loopback 必须成功、两个非 loopback 必须失败、两个 reject counter 都增加，root 四项仍成功、listener 仍在且旧 8000 不变。超时/无路由/仅脚本退出 0 不算通过
5. 先停本次探针并确认无残余，删除仅本次新增测试地址。若审批决定继续首次部署，可保留已加载且通过实测的正式 guard；否则在无同 UID 进程后 `systemctl stop aifinance-preview-egress.service`，只由 helper 清理其自有表。不要套用原文删除临时表的命令去删正式表
6. 实际 API/web/迁移必须通过自己的启动前 root verify；验收缺表/guard 启动失败时应用不会启动，以及正常停止 guard 会先停新应用。故障测试只可在先停 preview、确认无同 UID 进程后，以明确审批的方法注入，不能对运行中的应用故意拆掉保护。记录真实 cgroup v1、UID、CapEff=0、NoNewPrivs=1、回环监听和资源证据

本地 mock 无法证明目标 nft JSON 输出与模板完全一致。真实 nft 1.0.4 若输出额外对象或不同表达形式，核验会保守失败，应保留证据审阅兼容性，而不是放宽为仅匹配表名/注释。未通过目标解析、真实双栈 counter 和最终启动顺序之前，禁止宣称已验收。

## 本地测试

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/tests/egress-guard-check.py
PYTHONDONTWRITEBYTECODE=1 python3 scripts/tests/isolation-probe-check.py
```

本地 guard 18 项 mock 测试在 Python 3.12 与既有 Python 3.6.8 构建通过；原 probe 10 项通过。覆盖只匹配 app UID、固定新表、已有表/查询失败/校验失败拒绝、失败保留归属、精确语义与顺序、双栈计数器、仅按自有 handle 删除、同 UID 进程阻止拆保护、非 root/可写路径拒绝及 unit 权限分离。没有运行真实 nft 或目标测试；本地 `systemd-analyze verify` 因 `/run/systemd` 只读无法完成，不能计为验证通过。
