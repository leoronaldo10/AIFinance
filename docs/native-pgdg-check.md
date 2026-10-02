# PG17：下一次有界 DNF 事务预览

这是**待单独授权、待目标机执行的标准 DNF 命令**，不是安装器，也不是服务器兼容性验收。这里不交付自制 Python/DNF API checker；本地 mock 测试不能证明目标 DNF/libdnf 行为。

## 已知事实与本次目的

目标 Alibaba Cloud Linux 3 的普通 root DNF 缓存查询已成功，当前仓库为：

`alinux3-module, alinux3-os, alinux3-plus, alinux3-powertools, alinux3-updates, base, epel, epel-modular`

已有 PostgreSQL 模块含默认 10，原有缓存没有 PG17 候选。首次获批 PGDG CHECK 已下载官方 metadata（约936/685 KiB），明确显示 postgresql17/server/contrib 被 modular filtering 拦截、退出1且未安装。本版仅为同一次调查将两个临时 PGDG repo 的 module_hotfixes 设为 True；不改系统模块状态。不能因此认定 PG17 无法安装；下一步只求出 PGDG17 EL8 的**完整候选事务**。保留真实系统配置、RPMDB、模块状态及 host releasever，不再使用 `--config=/dev/null`、虚构 installroot 或全局 `--releasever=8`。

用户随后在目标重跑 True 修订，已得到完整 add-only 事务：`postgresql17`、`postgresql17-libs`、`postgresql17-server`、`postgresql17-contrib`，全部 `x86_64 17.11-1PGDG.rhel8.10`、来源 `pgdg17-check`；共 4 个新增包，约 10 MB 下载 / 44 MB 安装，无升级、删除或额外依赖。`Operation aborted` / exit 1 是本次 --assumeno 的预期终止。该结果允许准备精确四 RPM 与签名/脚本审阅，**不代表已批准或完成安装**。

[阿里云官方指导](https://www.alibabacloud.com/help/en/ecs/user-guide/build-a-primary-or-secondary-postgresql-architecture) 明确给出 Alibaba Cloud Linux 3 使用 EL8 PGDG 的路径，当前示例为 PG18。它说明调查方向合理，不证明这台旧版本主机的 PG17 依赖已满足。官方 [PG17 EL8 仓库](https://download.postgresql.org/pub/repos/yum/17/redhat/rhel-8-x86_64/) 确实有 17.11 RPM；实际选中版本仍由本次完整输出确认，不凭网页目录固定安装。

[PGDG 的 EL8 PG17 spec](https://github.com/pgdg-packaging/pgdg-rpms/blob/master/rpm/redhat/main/non-common/postgresql-17/EL-8/postgresql-17.spec) 包含 ICU、OpenSSL、压缩库、systemd 以及账号创建相关依赖/脚本。源码 spec 可能领先于仓库 RPM；它不是 RPM 的确切依赖闭包。尤其不能用 glibc 2.32 或 OpenSSL 1.1.1k 的版本输出代替对 ICU SONAME、具体包 build、脚本及已有依赖的审阅。

## 要先批准的精确范围

一次 root CHECK，最多 180 秒（超时先终止，5 秒后强制终止）：

- 临时加入本进程的两个固定 HTTPS 仓库：PGDG 17、PGDG common 的 `rhel-8-x86_64`；不写 `.repo` 文件，不安装仓库 RPM
- 复用 `/var/cache/dnf` 已有元数据，临时设置 `metadata_expire=-1`，不因到期主动刷新；**缺失或不可用时仍可能下载元数据**，因此这不是离线步骤
- 网络只供以上 PGDG 仓库，以及已确认的八个系统仓库配置对应源的必要元数据使用；可能涉及它们配置的镜像及元数据签名验证所引用的公开 key 文件：libdnf 可能先读取/下载公开 key、再询问是否导入；该询问会被拒绝。这不是批准导入。该步骤不下载 RPM 包，不索取/传输应用凭据
- 允许普通 DNF 元数据、solver cache 和锁写入 `/var/cache/dnf`。新缓存保留，不能把它描述成完全无文件写入。日志和 DNF persist 临时文件写进新建的私有 `/var/tmp/aifinance-pgdg-check.*`，正常退出时删除
- 不导入密钥、不修改模块、系统 releasever、账号、服务、防火墙、安全设置、软件包或数据目录
- 只预览固定四个 PG17 包；关闭弱依赖，缺仓库/依赖则报错，不跳过、不擦除、不自动选旧版本绕过

网络和总磁盘量**没有硬字节上限**，不能把超时当成字节配额。命令使用一个并行下载、每连接 15 秒超时、1 次重试，并限制本进程地址空间 768 MiB、单文件 128 MiB、CPU 120 秒；这不是 cgroup 或全局限制。执行前须确认 `/var/cache/dnf` 所在盘至少 1 GiB 可用；不够就停，不能自动清缓存。若必须严格限定总下载字节或总临时占用，应先另行设计，不能把下面命令当作已经做到。

## 获批后，在已有可信管理员终端执行一次

不要把这段放进部署账号的 forced-command gateway，也不要扩大 sudo 权限。下面不接受自定义命令或 URL；仓库列表与上面的目标回执一致。它读取普通系统 DNF 配置并禁用插件。插件提供的额外策略不会运行，因此安装前仍要核对是否有必须保留的插件策略。

```bash
env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ LANG=C LC_ALL=C /bin/bash --noprofile --norc <<'CHECK'
set -u
umask 077
[ "$(id -u)" -eq 0 ] || exit 2
[ "$(df -Pk /var/cache/dnf | awk 'NR==2 {print $4}')" -ge 1048576 ] || exit 2
work=$(mktemp -d /var/tmp/aifinance-pgdg-check.XXXXXX) || exit 2
trap 'rm -rf -- "$work"' EXIT
mkdir -m 700 "$work/log" "$work/persist" || exit 2
ulimit -v 786432 || exit 2
ulimit -f 131072 || exit 2
ulimit -t 120 || exit 2
/usr/bin/timeout --kill-after=5s 180s /usr/bin/dnf \
  --noplugins --assumeno --best --color=never \
  --setopt=assumeyes=False --setopt=install_weak_deps=False \
  --setopt=skip_if_unavailable=False --setopt='*.skip_if_unavailable=False' \
  --setopt=metadata_expire=-1 --setopt='*.metadata_expire=-1' \
  --setopt=timeout=15 --setopt='*.timeout=15' \
  --setopt=retries=1 --setopt='*.retries=1' \
  --setopt=max_parallel_downloads=1 \
  --setopt=gpgkey_dns_verification=False \
  --setopt=cachedir=/var/cache/dnf \
  --setopt=logdir="$work/log" --setopt=persistdir="$work/persist" \
  --repofrompath=pgdg17-check,https://download.postgresql.org/pub/repos/yum/17/redhat/rhel-8-x86_64/ \
  --repofrompath=pgdg-common-check,https://download.postgresql.org/pub/repos/yum/common/redhat/rhel-8-x86_64/ \
  --disablerepo='*' \
  --enablerepo=alinux3-module,alinux3-os,alinux3-plus,alinux3-powertools,alinux3-updates,base,epel,epel-modular,pgdg17-check,pgdg-common-check \
  --setopt=pgdg17-check.sslverify=True --setopt=pgdg-common-check.sslverify=True \
  --setopt=pgdg17-check.module_hotfixes=True --setopt=pgdg-common-check.module_hotfixes=True \
  install postgresql17.x86_64 postgresql17-libs.x86_64 postgresql17-server.x86_64 postgresql17-contrib.x86_64 </dev/null
status=$?
printf '\nPGDG_CHECK_DNF_EXIT=%s\n' "$status"
exit "$status"
CHECK
```

保留 `Dependencies resolved` 后的**完整事务表、总下载大小、安装大小和最终结束原因**，或完整依赖错误。只返回本次终端输出，不附环境文件、凭据、服务日志。

标准 `--assumeno` 到确认点返回 `Operation aborted` / 非零是预期结果；非零本身不证明已解析成功。若因超时、资源、签名、未知 key、缺失依赖或模块过滤而提前中止，该部分为 UNKNOWN，不能改成 `-y` 重试，也不能偷偷禁用签名检查。

[DNF 命令说明](https://dnf.readthedocs.io/en/latest/command_ref.html) 支持临时 `--repofrompath`、仓库选择、`--best` 和 `--assumeno`。[DNF 4.7 CLI 源码](https://github.com/rpm-software-management/dnf/blob/4.7.0/dnf/cli/cli.py) 在确认之后才进入 RPM 下载、包签名检查和真正事务；[key-import callback](https://github.com/rpm-software-management/dnf/blob/4.7.0/dnf/cli/output.py) 则先检查 assumeyes，因此这里同时显式设置 `assumeyes=False`，不只依赖 `--assumeno`。目标具体版本若行为/选项不同就停止审阅，不以源代码研究代替目标回执。

不使用 `--downloadonly` 或 `tsflags=test`：这些会下载 RPM，后者还可能处理导入密钥。当前阶段完全不需要它们。

## 如何判断，不把 CHECK 当作安装授权

可进入下一次审阅的唯一窄范围：

1. 四个同一 PG17 build 的核心包，来自上述 PGDG17 仓库
2. 解析实际要求的**新增**必要运行时依赖，例如某个确切 ICU 包；每项都须说明依赖关系、NEVRA、架构、来源和大小。`libicu` 只是调查例子，不是预先批准任何 ICU 更新
3. 没有任何 Upgrade、Downgrade、Remove、Replace、Obsolete、Reinstall，没有对已有同名包或旧 PostgreSQL 的改变；不替换 glibc、libstdc++、OpenSSL、systemd、Node/Python 等系统运行时

任何现有包变更、跨发行版替代、未知来源、额外 PostgreSQL 大版本、自动服务启动或不明脚本副作用，都超出上述 new-only 范围，停止。**完整事务表仍不包含所有脚本/file-conflict/签名证据。** 后续安装前要把完整候选 NEVRA、可信来源/发布 key 指纹、RPM 签名与完整依赖闭包、包脚本和服务副作用一起审阅，并取得明确安装批准。仓库会变化，执行安装前还须比对事务与批准清单一致。

首次目标回执已明确 PGDG 包受模块过滤，因此当前命令仅对两个临时 PGDG 仓库设置 `module_hotfixes=True`：这些仓库的包不被模块过滤，但其他仓库和系统模块状态保持原样。这不是全局 `module disable postgresql`，不是永久配置，也不保证包必然获选。依据 [DNF modularity](https://dnf.readthedocs.io/en/latest/modularity.html)，repo 的 module_hotfixes 是支持的例外机制；必须仍用完整事务表确认不会改变既有包。

## 本地验证边界

已检查本文 shell 语法。初版标准命令由用户在目标执行，只下载官方 metadata，随后因模块过滤失败，未安装。True 修订已由用户在目标完成依赖预览并得到上述四包事务；本助手没有目标终端执行权限。没有 RPM 下载、安装、密钥导入或发布。真正结果只以目标回执为准。若经审阅后继续推进，数据库凭据须在用户本地可信管理员流程中生成，DB/units/UID 网络隔离仍按各自独立批准范围执行。
