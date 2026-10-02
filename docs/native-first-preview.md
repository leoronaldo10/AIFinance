# 第一次个人预览：剩余执行批次

本页是待批准的执行方案。2026-10-02 的目标回执已确认独立 Node 24.21.0 和四个 PGDG 17.11 RPM 安装成功；默认 `postgresql-17.service` 已 mask、inactive、未 initdb。不要重复安装。尚未在服务器执行本页的新脚本。

## 看见页面只剩四步

1. **安装已审文件，初始化空库**：复用已有 `postgres` UID/GID 26。新集群 `/var/lib/pgsql/aifinance-preview`，新 root 配置 `/etc/aifinance-preview-db`，socket `/run/aifinance-preview-db`，仅 `127.0.0.1:55432`。不增加 OS 账号，不使用默认 PG cluster/unit。与早期 `aifinance-pg` 草案相比，这减少一个账号；代价是新 DB 与 PGDG 默认身份同 UID，目前没有其他 PG 实例。本机生成数据库、session、图片签名三个独立随机 secret，管理员密码由本人在 root 终端隐藏输入两次，写 `/etc/aifinance-preview.env`，root:aifinance 0640，不回显或上传。
2. **加载和实测 UID 规则**：DB/API/web 三个业务 unit 外，增加一个 root oneshot `aifinance-preview-egress.service`。它只维护独立 nft inet 表 `aifinance_preview_egress_v1`，仅匹配现有 aifinance UID，放行 loopback、拒绝其余 IPv4/IPv6。先证明此 UID 没有其他业务/8000进程。按 [正式表验收](native-egress-guard.md) 复用既有受限探针，真实验证双栈拒绝 counter、loopback 成功、root 对照与实际 cgroup v1 内存边界，清理本轮临时地址/探针。此过程不 reload/restart firewalld。
3. **构建上传、迁移和启动**：把这一批代码审查/测试后提交到 fix 分支；另批准 release 分支前进到确切审阅 SHA，并保留 GitHub Environment 人工审批。`stage` 操作在云端构建，只经现有受限 key 上传固定 SHA/hash 的制品，不运行它。root 首发脚本以 deploy UID 解包、以 aifinance UID 的限额 transient unit 运行迁移和仅话题种子，然后启动 API3101/web3100。所有端口只 loopback。验收真实 SHA、schema、PG权限/扩展、PID/UID/NoNewPrivs/空capabilities、内核 memory limit、初始failcnt与原8000监听不变。
4. **本人打开页面**：在本人电脑用原有管理员 SSH 认证创建 `127.0.0.1:3100 → 服务器127.0.0.1:3100` 本地转发，打开 `http://127.0.0.1:3100`。该新增转发需明确批准；不改受限 deploy key 的禁止转发，不开公网端口/安全组，不启第三方隧道。第一次页面可用不等于无人值守部署验收完成。

## 一次审批具体包括什么

- 已审文件下载及 root 保护的 helper 更新；原四个 helper 先校验确切旧 hash并备份，未知版本拒绝；新文件/units 已存在则拒绝覆盖。仅 `daemon-reload`，不修改 sshd/sudo/key
- 提前开放受限 gateway 的 **upload 数据写入**，使用现有 128 MiB、300秒、SHA256、不可覆盖限制；此权限在 native-ready 前可用。deploy/rollback 仍需 ready，shell/SFTP/端口转发仍不允许
- DB initdb、仅专用库/非superuser角色、SCRAM、pg_trgm、受保护 env、四个固定 service unit；此次只 start，不 enable 开机自启
- UID 独立 nft 表和固定短时验收探针：仅本轮新建的 lo 地址 `192.0.2.254/32`、`2001:db8:ffff::254/128`、TCP48173、列明 transient probe units。冲突即停，不删他人对象
- 固定制品上传、首次空库迁移、仅话题种子，启动三个新业务服务。API320MiB/web256MiB/DB256MiB；迁移320MiB与应用串行，Node堆128MiB；DB shared_buffers32MiB、12连接、work_mem1MiB，较旧64MiB草案降低初次负载
- 用户电脑的单一 SSH 本地转发。若原管理员认证不能从电脑使用，先解决已有登录路径；不擅自新增密钥/开启root登录/修改SSH策略

所有代码当前仅本地准备。发布到 GitHub、release 分支前进、目标脚本运行与网络修改，须分别包含在明确批准的批次内。无需 LLM API key，不启动 worker/模型/采集/飞书/IndexNow。

## 审阅后的实际执行顺序

制品身份将在代码封版后写入独立 manifest；下面 `<…>` 是必须由最终发布 SHA/hash 填入的参数，不能照字面执行。下载继续使用已经在目标成功的 GitHub contents API 固定 commit，避免已失败的 raw 域名；不需要服务器保存 GitHub token。

1. 从固定 commit 取得本批 helper、unit、`preview-files.json` 到已有 root 保护的 `/root/aifinance-native-inputs`。逐文件 SHA核验后，执行：

```sh
python3 -I -B /root/aifinance-native-inputs/install-preview-files.py --manifest-sha256 <manifest-hash>
python3 -I -B /root/aifinance-native-inputs/install-preview-files.py --manifest-sha256 <manifest-hash> --apply
python3 -I -B /root/aifinance-native-inputs/provision-database.py check --script-sha256 <db-script-hash> --unit-sha256 <db-unit-hash>
python3 -I -B /root/aifinance-native-inputs/provision-database.py apply --script-sha256 <db-script-hash> --unit-sha256 <db-unit-hash>
```

所有命令以干净 `env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ LANG=C LC_ALL=C` 前缀执行。DB apply 必须保留真实 stdin/stderr TTY，不能管道输入密码。不要复制 env 或完整日志到聊天。脚本只输出固定错误类别和非秘密成功事实。

2. 非root Node `--version`/内置crypto轻量测试，随后正式 guard start和双栈探针。probe源文件由安装器安装到 `/opt/aifinance/bin/isolation-probe.py`。以当前 docs 的固定流程为准，不能为了通过删除保护、跳过IPv6、改变UID或只测试“连不上”。先完整取得网络证据再执行任何上传应用代码。

3. `stage` 工作流返回 STAGED_ONLY 的 SHA与archive SHA256。随后root调用：

```sh
python3 -I -B /opt/aifinance/bin/first-preview.py check <release-sha> <archive-sha256>
python3 -I -B /opt/aifinance/bin/first-preview.py start <release-sha> <archive-sha256>
```

`check`仅检查当前先决条件；`start`只支持首次、当前指针和schema/ready均不存在的状态。它不会重试已有或部分初始化状态。迁移程序/seed/应用始终在 aifinance 下；root健康探针只访问两个固定loopback目标且拒绝重定向。app-owned schema对象通过真实非superuser数据库连接读取，避免superuser执行被替换的view。

systemd239 文件 unit支持 `ExecStartPre=+`，transient API不支持该前缀。因此一次性迁移在root紧邻启动前调用固定guard verify，随后 transient 加 BindsTo/After。此执行窗口与整个预览运行期间禁止并发firewall维护；oneshot不持续监控其他root删除规则。未来若需firewall维护，先停preview，再审阅/验证后启动。见[上游v239 transient解析](https://github.com/systemd/systemd/blob/v239/src/shared/bus-unit-util.c#L234-L262)。

4. 本人电脑，沿用原本可用的管理员SSH认证：

```sh
ssh -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -L 127.0.0.1:3100:127.0.0.1:3100 root@47.94.47.49
```

首次host key确认必须与已可信的主机指纹比对，不能忽略/关闭检查。访问成功后在本机网页输入刚设置的管理员密码。

## 失败与就绪范围

首发失败只停止本批 API/web/DB；guard保留，数据库/配置/env/制品/当前指针保留。没有旧版时不宣称回滚。先检查部分状态，不能重跑初始化/删库/覆盖env。若script提示stop失败，由管理员只停这三个精确unit。

成功写 schema指纹，但 **不写 native-ready**。输出真实初始资源数据与 `pressure_and_reboot_accepted=false`。最终人工合并双栈规则计数、实际服务资源、正确release、私有访问、原8000健康证据，再决定是否给后续自动发布开ready。当前不自动enable，重启恢复和持续负载/OOM测试仍未验；不要为了第一次看页面假造这些证据。

允许loopback不阻止利用本机relay间接外联；API/web同UID也不是秘密文件强隔离。当前是可信已审代码、单人、低负载预览。不要把它描述为能够运行任意敌意代码的完全沙箱。
