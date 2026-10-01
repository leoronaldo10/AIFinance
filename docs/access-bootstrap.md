# 一次性接入：用户执行，先检查后应用

本步骤只建立专用持续访问。**不安装 Node/PostgreSQL、不安装或启动 systemd 服务、不迁移、不部署、不改全局 sshd/firewall，不操作其他业务进程。** 配置成功以后，GitHub runner 可以在用户电脑关闭时执行已授权操作；首次仍需用户在可信终端完成密钥与账号初始化。

## 必须先确认的范围

默认名称是 `aifinance-deploy`（接入）与 `aifinance`（运行），根目录 `/opt/aifinance`；服务仅为 `aifinance-preview-api.service`、`aifinance-preview-web.service`。如果另一会话已经建立任一账号、目录或服务，脚本拒绝继续，不能覆盖或“自动接管”；先协调现有部署。未确认这点前不要执行 apply。

新增权限逐项为：创建两个系统账号/组；创建专用目录；在管理员持有的 home 写入一条受限公钥；安装管理员持有的入口脚本；增加一条只匹配两个精确服务重启命令的 sudoers 规则。不给远程 shell/SFTP/SCP、PTY、agent/端口/X11 转发，不允许任意 systemctl 或 root 命令。不会把服务定义、启动脚本、sudoers 或 authorized_keys 的写权限交给部署账号。

目录顶层和 bin/shared 由 root 持有；部署账号仅拥有 incoming/releases/state；运行账号仅拥有 shared/data。`state/current` 是发布链接。上传代码不以部署账号运行，只有以后批准安装的受限 app 服务才执行。`native-ready` 尚不存在时 forced-command 只允许 `verify`；初始化脚本不会创建该验收标记。

## 1. 用户 Windows 终端生成一次性专用身份

在**用户自己的 PowerShell**执行，而非 ChatGPT/其他 AI 终端。先确认目标文件不存在，避免覆盖：

```powershell
$key = "$env:USERPROFILE\.ssh\aifinance_actions"
if ((Test-Path $key) -or (Test-Path "$key.pub")) { throw "文件已存在，停止；不要覆盖现有密钥" }
New-Item -ItemType Directory -Force "$env:USERPROFILE\.ssh" | Out-Null
ssh-keygen -t ed25519 -f $key -C "aifinance-actions"
```

这是无交互 Actions 专用密钥：在口令提示处留空，明确只用于下述受限账号。私钥保留在自己的受控设备及受限 Environment Secret，不回传聊天、不上传仓库、不交给其他 AI。公钥 `$key.pub` 可以复制到阿里云网页终端，保存为仅包含一行 `ssh-ed25519 ...` 的文件；不要复制没有 `.pub` 后缀的私钥。

## 2. 先配置 GitHub Environment，再放私钥

在仓库 Settings → Environments 创建 `aifinance-preview`。Deployment branches and tags 必须选择 **Selected branches and tags**，仅添加 **Branch** `release/aifinance-preview`，不加 tags、通配符或 PR refs。不要使用“Protected branches only”代替，因为没有保护规则时可能放行所有分支。

同时配置该发布分支的保护/ruleset，仅允许可信操作者推进已审阅代码，工作流改动也必须审阅。不允许不可信协作者绕过。实际 UI、权限和保护效果须确认；无法限制时停止，不把私钥降级为 Repository Secret。这里仍依赖仓库管理员可信，管理员可以修改环境和保护策略；如需要每次人工批准，可另外加环境审批，是否可用以实际设置为准。

在这个 **Environment**（不是 Repository secrets）里手动添加：

- `AIFINANCE_SSH_HOST`：目标 ECS 公网地址，不写入代码。
- `AIFINANCE_SSH_PORT`：已确认的 SSH 端口。
- `AIFINANCE_SSH_KEY`：专用私钥全文。直接从本机文件复制到 GitHub；不在终端打印给 AI，不粘贴聊天。保存后清理剪贴板。
- `AIFINANCE_SSH_KNOWN_HOSTS`：按下一节可信终端核验得到的主机公钥记录。

已存在的同名项先核对用途，不直接覆盖。此前 IP-only 的 `ECS_DIAGNOSTIC_HOST` 可继续保留用于 TCP 诊断，它不是 SSH 身份。实际创建 Environment、分支保护和 Secrets 均由用户操作，本代码不会代为修改设置。

## 3. 在可信阿里云网页终端核验主机公钥

只读公开主机密钥，不读取没有 `.pub` 后缀的文件：

```bash
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
cat /etc/ssh/ssh_host_ed25519_key.pub
```

用可信终端展示的公钥构造 known_hosts：默认 22 端口为 `目标地址 ssh-ed25519 公钥Base64`，非默认端口为 `[目标地址]:端口 ssh-ed25519 公钥Base64`。核对 SHA256 指纹后存入 Environment Secret。不以未经核验的 ssh-keyscan 结果代替，不关闭 StrictHostKeyChecking。

## 4. 在 ECS 网页终端先检查，再人工决定应用

仅在**可信的 ECS 管理员网页终端**执行。将本次已审阅提交的 `deploy/native` 文件放入 root 持有、其他用户不可写的审阅目录（例如 `/root/aifinance-access-review`）；包括 bootstrap、gateway、release、launcher。应通过固定提交取得，禁止 curl 下载后直接 pipe 到 shell。此处路径以实际保存位置为准。

公钥保存为 `/root/aifinance-actions.pub` 后，先运行只读预检（会产生临时校验文件，但不创建账号或授权）：

```bash
python3 -I /root/aifinance-access-review/bootstrap-access.py --public-key /root/aifinance-actions.pub
```

输出 `CHECK ONLY` 后，确认上述每项持久变更和冲突检查，再执行：

```bash
python3 -I /root/aifinance-access-review/bootstrap-access.py --public-key /root/aifinance-actions.pub --apply
```

脚本会检查现有账号/组/路径/同名服务、sshd 的 key 路径和环境策略，验证公钥格式、sudoers 精确语法。任何冲突均停止，不自动覆盖。应用阶段意外失败可能留下新建的部分对象；不要反复重跑或自动清理，先由管理员核查。脚本使用密码锁定的系统账号；某些 PAM/sshd 策略可能拒绝公钥登录，若发生要单独诊断，不自动解锁密码或放宽全局策略。

没有安装 systemd unit，重启授权只是为已设计的两个名字预留；不存在或尚未批准的运行环境不能发布。服务定义以后仍须由 root 单独审阅安装。初始化不会创建数据库配置或 `native-ready`。

## 5. 验证与后续免手工操作

第一次只运行 `verify`，必须返回 `AIFINANCE_ACCESS_OK`，这代表专用公钥认证和强制命令入口可用，不代表应用已经上线。工作流把构建与持钥操作放在不同 runner；持钥任务不检出、不执行上传代码。可信发布分支 push 只触发 verify，绝不会自动部署。现有草稿分支和诊断分支不在环境允许名单内。

初次验证可在**另行批准创建可信发布分支**后，由 `release/aifinance-preview` 的 push 触发；这一步不是 bootstrap 自动执行的内容。以后手动操作默认 build，明确选择 deploy/rollback 才调用对应入口。尚未进入默认分支的 workflow 没有手动触发入口时，不为此擅自合并 main。

待 Node 24.11+、独立 PostgreSQL、网络限制、HTTPS、服务安装和数据验收完成后，再单独授权创建 root-owned native-ready/schema 标记。只有这时才开放上传和发布命令；代码回滚不恢复数据库。

撤销接入由可信 ECS 管理员移走/禁用 `/var/lib/aifinance-deploy/.ssh/authorized_keys` 中该专用条目，并删除对应 Environment 私钥 Secret；单纯锁密码不能撤销公钥。密钥轮换或复用已有账号需要独立审阅，bootstrap 故意不提供覆盖模式。

给另一位 AI 的单行提示（仅审阅，不执行）：

> 请只读审阅 AIFinance 固定提交的 docs/access-bootstrap.md 与 deploy/native/bootstrap-access.py，核对现有账号、/opt/aifinance、两个指定服务及 GitHub Environment 分支限制，列出冲突和待确认项；不要执行 apply、生成或读取私钥、安装运行时、改 sshd/firewall、启动服务或部署。
