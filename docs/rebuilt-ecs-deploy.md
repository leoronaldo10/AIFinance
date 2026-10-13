# 重建 ECS：受限发布准备（未部署）

## 2026-10-13 状态与证据边界

现场报告：同版 bootstrap 已验收 same_version_ready；switch/current 指向原
staging/d57ba047369e666025347719caee1a4c642abe62。两个服务 User=aifinance-deploy，
WorkingDirectory=switch/current，EnvironmentFile 仍是原 staging/.env。
账户 uid999/gid988，passwd HOME=/home/aifinance-deploy、shell nologin；
两个 root 管理的 90-home-compat.conf 保持进程 HOME=/opt/aifinance。
固定只读代理已在现场验证身份、链接、服务和 HTTP，并关闭 WebSocket。
这些是现场报告，不是本轮直接连接验证。备案仍 pending，只承诺 localhost
3000/3001 和 PostgreSQL 55432 回环；公网端口、域名、HTTPS 不在本轮范围。

本轮仅本地代码/测试。PR #4 保持draft；后续离线代理适配见 [固定代理适配](rebuilt-proxy-adapter.md)。
现有代理仅获准固定只读，不因为 RAM 限制实例和用户就具有技术上的命令只读边界。
临时 STS 已有明确到期时间，不假定仍有效或自动续签；长期凭据及扩权没有批准。

## 最小版本与兼容性

固定 rebuilt-v1 文本命令及 SHA/digest/operation ID 格式不变。
root policy 升为 version=2，旧 policy 被拒绝，不自动迁移。新增字段：

- approved_artifacts：管理员批准的完整提交 SHA → 实际 tar.gz SHA-256；每次新发布
  先审阅该精确配对。上传及发布均验证，续作在切换前再次验证；撤销批准后已开始
  的切换进入恢复，不阻止恢复已记录的旧版。
- rollback_targets：管理员明确验收、批准回退的已安装 SHA 列表（可包含基线）。
  不是任意目录名；核对来源、制品及当前文件后才可录入，不能自动接纳上传版本。
- helpers_sha256：/opt/aifinance/bin 下 rebuilt-gateway.py、extract-release.py、
  rebuilt-launch.py 三个 root 管理文件的摘要；路径集合和内容必须匹配。
- units：原六属性中 ExecStart 改为 {path, argv}，只忽略 systemd 的执行时间/PID等
  结果字段，拒绝额外命令；新增 HOME 和 files_sha256（fragment及所有drop-in摘要）。
  policy不保存其他Environment值或unit正文。HOME检查是systemd配置值；启动入口
  再检查实际继承HOME，拒绝EnvironmentFile等覆盖成其他值。

回执增加布尔 fallback_allowed；旧回执不自动升级，会失败关闭，管理员须审查，
不得删除或补造。bootstrap 的 root-only 回执格式不变，与发布回执分开保存。
模板 accepted:false，批准列表为空，不能原样启用。
policy 的 current_link 和 releases_dir 必须分别为 /opt/aifinance/switch/current
和 /opt/aifinance/releases，与启动入口一致；其他布局在变更前拒绝。

## 启动与 HOME

rebuilt-launch.py 是拟安装的 root 管理入口，不从新包执行部署脚本。
两个服务分别新增审阅后的 95-rebuilt-launch.conf，内容来自
rebuilt-launch-api.conf / rebuilt-launch-web.conf；仅覆盖 ExecStart。
继承原 EnvironmentFile、WorkingDirectory和90-home-compat.conf。
固定 /usr/local/bin/node --experimental-strip-types 启动两应用，不迁移/seed。
入口验证实际 cwd 为基线staging或releases/<SHA>，与switch/current一致、标记匹配，
再设置 AIHOT_RELEASE。基线也必须先同版重启并返回真实SHA，不能伪填env或放行dev。
配置和启动过程中不读取/复制.env文件；不输出继承的秘密。
旧run-preview.py的路径、端口和配置契约不同，不可直接套用。

bootstrap恢复现在仅额外允许root可信的90-home-compat.conf，字节必须为：
`[Service]\nEnvironment="HOME=/opt/aifinance"\n`（实际换行）。其他内容、任意其他
文件或不可信属主权限均在删除前拒绝；恢复保留HOME文件及其目录。
安装95-rebuilt-launch.conf后，不可用bootstrap rollback回退阶段二；它会拒绝未知
文件。阶段二失败应先由管理员恢复该阶段的精确unit变更，再按适用范围恢复。

## 制品与发布流程

1. 在无生产凭据的构建环境检出完整获批SHA，运行测试/构建，再运行package.sh。
   保存构建来源、原tar、摘要、操作ID；GitHub祖先检查只约束既有SSH workflow，
   当前代理不得省略相同准入。哈希本身不是来源证明。
2. 管理员在version=2 policy批准该SHA/摘要及已验收的回退目标。构建包不携带秘密。
3. 固定upload有128MiB限制，重复同SHA不同字节拒绝；服务器只运行root可信解包器，
   不执行包内安装、npm、迁移或部署脚本。解包器验证路径/类型/链接/资源限额。
4. deploy先校验旧版结构与健康，再记录意图、校验新包/SQL、原子换链和联合重启。
   健康要求两个服务active、Web HTTP成功、API ok=true/db=ok/release=完整SHA，
   3000/3001/55432精确回环。失败恢复已记录的旧版；有短暂重启中断，不是零停机。
5. 当前版本不健康时，新的rollback仍可切往policy批准且结构校验成功的目标。
   回执记录是否有可用的原版回退点；没有时若恢复目标也失败，保留当前现场并置
   recovery_required，不再次切回已知坏版本。缺失/未知current路径仍失败关闭。

SQL清单和实际迁移文件必须与已验收基线一致；网关不查询/迁移数据库。
数据库verified是管理员验收声明。现有账户历史只有SELECT；不得推断写入权限，
新应用必须兼容该权限。代码回退不能撤销schema、数据或其他运行副作用。

原EnvironmentFile固定指向旧staging/.env，后续版本继续依赖它，因此不得清理
基线staging。首版不迁移秘密；新版本需要配置变化时另批。
应用与部署同UID，可修改其有权写入的发布文件/状态；root批准清单不是应用文件
不可变证明，回执不是防篡改审计。精确sudo restart不等于强隔离；本轮不新建账户。

## 一次批准范围（尚未批准或执行）

- 安装root:root管理的三个bin helper、更新bootstrap副本/摘要（若需要其恢复兼容），
  version=2 policy及两个95-rebuilt-launch.conf；审核实际文件diff与摘要，安装文件清单见
  deploy/native/rebuilt-release-files.sha256。
- 仅预置/授权 /opt/aifinance/incoming、releases、state/rebuilt（部署用户0700）及
  switch目录内原子换链所需写权限；保留/opt/aifinance root:root0755，禁止递归chown。
- sudo仅精确 /usr/bin/systemctl restart aifinance-api.service aifinance-web.service。
  daemon-reload及unit安装由管理员执行；不授予任意systemctl、shell或DB迁移。
- 同版SHA启动验收、失败时恢复95 drop-in的管理员路径、短停窗口；之后才accepted。
- 另列首发SHA/摘要/操作ID、回退SHA、维护窗口和STS期限；不批准公网或长期AK。

固定upload现新增PTY安全Base64离线适配与artifact-status查询，deploy/rollback/status/resume
有离线协议检查与真实网关fixture集成。live入口仍锁定；大制品吞吐与API发送编排未验收，
详见 [固定代理适配](rebuilt-proxy-adapter.md)。本轮没有启用新远端能力。
旧deploy-rebuilt.yml仍是SSH通道，不因有只读代理就自动可用；不假定dispatch写权限。

## 断线和环境重建

服务器state/rebuilt保存操作回执和active ID，切链/回执使用原子替换及fsync，
flock防重复操作，固定systemd作业未结束时拒绝竞争。断线不保证后台任务继续。
重建云环境后恢复审阅版本工具、原制品与ID；先status/status ID，再决定resume ID。
不重建包覆盖原摘要，不删除回执。recovery_required、解包中断、文件已落盘但
artifact标记缺失、外部路径改变等停止人工审查，不保证任意断电点自动恢复。
工具/包的恢复不需要长期凭据；新STS经Personal Vault注入，不能视为自动续期。

本地验证使用临时目录和模拟systemd/HTTP；root CLI容器只对隔离文件系统作真实
属主权限检查。它们不是ECS验收。上线前仍须验证真实systemd属性格式、权限、启动、
健康、制品传输、断线恢复与回退。日志首版仍只返回时间/级别，不读.env或日志正文。

2026-10-13 独立安全审查发现并修复：非UTF8版本标记阻断恢复、policy路径与启动入口
固定布局不一致。版本标记解码失败现转为受控release_identity错误，损坏新版本可进入
既有回退逻辑；损坏旧标记不再阻止紧急回退。对应本地网关回归增加至43项。
