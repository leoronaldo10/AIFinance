# 固定只读 inspect 更新（尚未发布或应用）

本变更不安装运行时、不部署、不接触数据库或现有端口 8000 服务。独立变更基线为 c0908d1c9c8a089637cde3930c4a910805e43249；只有网关、检查器、更新器、专项测试、本说明及工作流 inspect 选项。不包含 bootstrap、首次准备、服务 unit 或 release 脚本变更。

## 权限与数据范围

精确命令 inspect 无参数、无 shell、无需 native-ready、以现有部署账号运行，无新增 sudo。只输出 OS 标识、内存/磁盘数值、五个指定端口的监听类别、三个指定服务的状态/内存、systemd 版本、cgroup 挂载类型、PostgreSQL 缓存模块/包及仓库标识、发布标记存在状态；不读取密钥、env、服务日志，不输出 IP 或仓库 URL。

子进程使用固定绝对路径，清空继承环境，HOME 和工作目录固定为 /。DNF 使用 -C --noplugins --config=/dev/null，并由固定参数指定系统 reposdir、varsdir、cachedir；不会读取部署账号的 HOME 或当前目录配置。配置树检查 root 所有权、不可组/其他用户写入，拒绝子路径符号链接，遍历限制 512 项/1 秒。仅检查缓存，不刷新、不安装；权限不足、缺缓存或配置不可信即 unavailable。临时日志/状态目录自动清理。repoquery 的关闭模块过滤仅作用于查询。

单命令 5 秒/16 KiB，命令总预算 35 秒，最终 JSON 64 KiB。空结果不证明版本不存在。不会测试真实 BPF 网络拦截或执行软件包安装事务。系统 root 配置、二进制与管理员属于信任边界；该入口不能防御已控制 root 的攻击者。

## 一次性管理员流程

先另行批准发布固定提交及服务器更新。将以下三份文件从同一已审提交保存到新的 /root/aifinance-inspect-review（root 持有，目录 0700，文件 0600，路径无符号链接），核对 SHA256，不从浮动分支下载，不 pipe 到 shell。当前尚无新提交 URL。

- `ssh-gateway.py`: `04a66f6b0475b7a02c9192ae703658ca98f0460250515c968ce59490984e77b1`
- `inspect-native.py`: `c631995399b6b2ec90926c8ce577d73c1d53c4b49655e33e36181c0f71a64151`
- `update-inspect.py`: `b1cf9afc4fd164a1a8b984229e31a7e2e9e53c842c505f4229555e5c7027566b`

旧网关必须为 SHA256 `0d93245bec09662c2392a28c4c6047ba0d6c46e45f881ac508ca0436c7b265f9`，与基线 c0908d1 文件一致；更新器会在服务器再次核对，不根据先前记录盲目覆盖。

在可信管理员终端，首先只检查：

```bash
python3 -I /root/aifinance-inspect-review/update-inspect.py --gateway-sha256 04a66f6b0475b7a02c9192ae703658ca98f0460250515c968ce59490984e77b1 --inspect-sha256 c631995399b6b2ec90926c8ce577d73c1d53c4b49655e33e36181c0f71a64151
```

确认 CHECK ONLY 后，同一命令加 `--apply`。脚本以独占新建方式保留旧 gateway 备份（0600），安装 inspector（0755），最后原子替换 gateway（0755）。未知旧哈希、已有 helper/备份或不可信父目录均停止。不更改账号、密钥、sshd、sudoers、服务或 native-ready，不要重跑 bootstrap。

若中断或需撤回：同一命令加 `--restore` 先检查，再加 `--restore --apply` 恢复。只接受已知旧备份、已知新/旧网关及已知检查器哈希，原子恢复旧网关并保留全部证据；不自动删除检查器或重试更新。备份损坏、文件未知或部分写入时停止人工检查。

更新后已有受限 SSH 身份可执行字面命令 inspect；Actions 必须使用已审批可信 release 分支上包含 inspect 选项的工作流。手动入口若尚未注册，仍需另行审批最小注册改动；本补丁不改变 main 或环境设置。verify 继续可用，push 仍仅触发 verify。

## 实际验证

`/tmp/aifinance-cpython368-src/python -B scripts/tests/inspect-check.py`：Python 3.6.8 实际执行 7 项通过；同一测试在 Python 3.12 通过。涵盖精确命令/注入拒绝、环境与工作目录净化、输出白名单/超时/大小、符号链接、缓存失败不提权、固定 DNF 配置、哈希校验、默认不写、重复拒绝、替换前中断及恢复。

测试运行时来自官方 CPython v3.6.8 提交 3c6b436a57893dd1fae4e072768f41a199076252；为兼容当前构建机新版 libc，仅将 mathmodule.c 内部静态 sinpi 函数及其调用重命名为 python36_internal_sinpi。不是未经修改的官方容器，也不是 ECS 原生运行证明。服务器未连接、未更新，PostgreSQL 来源等待 inspect 采样。
