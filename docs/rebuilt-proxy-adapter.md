# 固定代理发布适配：仅离线/mock

2026-10-13：基于 ed05b485 的 reviewed readonly-proxy-v3 原样来源实现。
没有读取 STS、调用云 API、建立外部 WebSocket、访问 ECS 或改变服务器。
readonly client 的 LIVE=false、来源和校验清单不变。旧 SSH workflow 不变。

## 已实现的边界

`deploy/native/rebuilt-proxy.py` 是协议核心；`rebuilt-proxy-session.py` 已实现完整单次
API发送→会话URL校验→WS→网关回执编排，测试注入传输工厂运行同一代码路径。
connection_plan 复用审查版 require_proxy、TLS验证、canonical query 和 ACS3签名；
只生成内存计划，不发送请求。凭据与 expiration 必须显式传入，不能从环境读取，
不使用只读源码里的历史 expiration。计划包含秘密，调用方不得打印或保存。
require_proxy 强制已有环境代理（NO_PROXY 不形成绕过）；证书与主机名验证保持开启。
生产组合复用原文件的 API connection、session URL/token 检查和 WebSocket connector。
run_live 在任何连接或文件写入之前由 LIVE_EXECUTION_ENABLED=False 拒绝，CLI也拒绝；
没有环境变量或命令行旁路。已写完整生产组合代码，后续批准的是启用和实测，不是补写编排。
该代码闸门不是OS权限隔离，不能替代RAM、服务器policy及人工批准。

固定 CommandLine 为 `/opt/aifinance/bin/rebuilt-gateway.py --terminal rebuilt-v1 ...`。
每参数严格验证、精确数量、最多512 ASCII字节，不调用shell、env、sudo命令包装器，
不允许传账号/实例/主机/可执行路径/下载URL。动作仅 verify、upload、artifact-status、
deploy、rollback、status、resume。Agent shlex直接exec的证据见本地官方
readonly-proxy-v3/official/shell_unix.go；原499字符只读shell命令不被复用。
网关原 SSH_ORIGINAL_COMMAND 通道保留；terminal 入口拒绝同时提供该变量。
服务端仍检查部署UID、root policy、批准SHA/摘要、文件/单位摘要、锁和回执。

输入布局严格按官方 AxtMessage.ts/AxtSession.tsx，复用审查版decode_frame。
适配额外只接纳已审阅1.02版本；其他版本需审阅，不能靠放宽检查接入。
Output须非空且一致的channel，连续序号；重复输出忽略，缺帧/Sync/异常状态停止。
不会重连、重放Input或自动重试API/发布。通道关闭不等于操作成功，须收到与请求
绑定的完整网关JSON回执；rolled_back/recovery_required保持原状态，不当作成功。

## 上传协议及尚存限制

官方Agent创建PTY并将Input写入PTY，不是原始binary stdin。新网关仅在专用PTY上传时
关闭echo、保留canonical mode，然后输出 `{"terminal":"rebuilt-pty-v1","ack":0}`。
每行是8位连续十进制块号、冒号、最多768原始字节的规范Base64和换行，最长1034字节，
低于Linux canonical line上限。每块等待网关ACK后再发下一块；ACK不等于落盘承诺。
显式 `.\n` 终止，不使用Ctrl-D、不依赖连接关闭作为完整上传标记。
网关拒绝坏编码、非规范padding、缺换行、超长行、乱序/重复块和超128MiB内容；
最终仍通过原upload的摘要验证、fsync和原子link才返回上传成功。中途失败清理临时文件。

编排在API发送前调用rebuilt-provenance.py独立校验，操作参数不能提供可信source声明：

- 默认读取客户端机器固定 `/etc/aifinance-proxy-approval.json`，root属主、不可组/其他人写、
  非链接；模板accepted=false。此为本地客户端批准记录，不是新服务器权限。
- 每个SHA的批准项精确包含sha256、run_id、artifact_id、workflow_id、run_attempt、
  workflow_sha256；repository固定为leoronaldo10/AIFinance。回退目标单独列出。
- 独立固定GitHub HTTPS GET读取workflow、run、artifact、该SHA上的workflow文件；必须
  经既有代理和TLS，不跟重定向，不使用metadata里的任意URL，不下载外部artifact URL。
  固定workflow路径为.github/workflows/deploy-rebuilt.yml；run须同仓库且非fork、
  workflow_dispatch、completed/success，head_sha、attempt和workflow身份须匹配。
- 调用方提供原始GitHub ZIP bytes，但外层摘要必须匹配独立API返回的artifact digest，
  ID/name/run/head_sha及expired=false一致；内层仅允许精确SHA.tar.gz及对应.sha256，
  核对实际tar摘要与管理员批准值。ZIP不解包到文件系统，不执行制品。
- 独立固定git命令核对当前干净checkout的HEAD等于目标SHA；workflow文件bytes匹配批准
  摘要。缺证据、缺API摘要、旧run、未批准workflow、工作区变化都在API发送前失败关闭。

固定GitHub读取支持现有只读Actions/Contents授权，不自动申请新权限、签发凭据或dispatch。
没有真实批准构建制品时不得放行。管理员批准、GitHub服务与其工作流仍是信任根；
这不是SLSA签名证明。测试的独立审批/GitHub/checkout reader仅为显式fixture注入。
依据：[GitHub artifact API](https://docs.github.com/en/rest/actions/artifacts)、
[workflow run API](https://docs.github.com/en/rest/actions/workflow-runs)。
发布/回退绑定32hex operation ID；上传由SHA/摘要识别，不冒充发布回执。

上传断线后显式调用固定 `artifact-status SHA DIGEST`：持共享锁、验证policy批准配对，
核对incoming文件真实摘要；present=true确认已提交，false仅表示查询时无完整制品。
竞争上传可能使锁拒绝；停止等待人工选择后续查询，不自动重传。SQLite本地journal在
API发送前以同步事务记录尝试；同SHA或operation ID重复发起会拒绝，包括进程重建后。
明确artifact-status返回present=false后，调用方可再次显式调用同SHA/摘要upload一次；
状态许可在发送前消耗，present=true不得重复上传。SHA同名异摘要失败关闭。
发布断线用status ID核对既有回执，再由调用方明确选择resume ID；保持原ID和原制品。
进入发送阶段的新status先撤销旧本地观察许可，随后请求失败也不保留旧许可；
resume消耗最新非终态回执，deploy恢复前重新验证来源；
已成功/已回退/recovery_required拒绝resume。观察回执还须与本地原请求身份一致。
不删除回执，不自动恢复recovery_required，不自动发起新operation。

离线exchange使用Unix主线程专用SIGALRM总时限（1..480秒测试参数），覆盖recv与阻塞send，
保留恢复原信号handler，已有timer则拒绝；服务器原480秒alarm不变。编排外层同一alarm
覆盖证据/API/WS I/O；超时后的close有独立最多2秒清理预算，总耗时最多操作预算+2秒。
这不是获批的真实上传/操作时间。768字节stop-and-wait上传128MiB需要174,763次往返，
480秒要求平均RTT低于2.75ms，实际代理大制品很可能超时。因此编排明确限制为最多1MiB，且满足
`15 + (ceil(bytes/768)+2)*0.25 <= seconds` 才允许API启动；超过限额直接拒绝。
这是250ms/往返的保守规划模型，不是已测WAN上限；真实网络更慢时仍超时停止。
1MiB真实本地PTY测试使用1367个Input帧，在本机约0.27秒完成，不能外推远程速度。
实际完整应用包若超过1MiB，当前客户端明确不准入，不能声称128MiB发布已可用。
首发必须按实际大小确认准入；需要扩大时应另评审有界传输策略，不增加shell/URL/账号权限。

## 验证与审批

`npm run test:rebuilt` 纳入核心适配14项和端到端编排13项：本地真实默认PTY的任意binary字节往返、坏输入、
摘要/来源、代理/TLS、错误版本/通道/序号、重复ACK、断线、阻塞发送时限、固定请求、
真实网关upload/artifact-status、受限解包/deploy、status与显式resume、重复操作无重启。
主机systemd/HTTP由既有fixture替代，真实发布状态机、临时文件/链接/回执和解包器参与。
新增编排测试覆盖真实g.main、断开API响应/WS、过期假凭据、错工作流/构建/ZIP摘要、
1MiB真实PTY、状态许可消耗和超时后阻塞清理。来源原70项及SHA256清单亦已本地重跑。
没有ECS实测或远程吞吐验收；API发送编排已经通过fake API端到端集成。

后续一次性服务器落地审批清单（本轮不申请、不执行）：

1. 明确实际首发SHA/制品摘要/构建run/operation ID、可信回退SHA、维护与回退窗口。
2. 审查并安装root管理gateway（含terminal入口）、extractor、launcher、policy v2，
   文件摘要以更新后的rebuilt-release-files.sha256为准；必要时同步bootstrap摘要。
3. 审核incoming/releases/state/rebuilt及switch最小写权限，不递归chown；同UID不强隔离。
4. 两个95启动drop-in、精确sudo联合restart、管理员daemon-reload及失败恢复步骤；
   保留原EnvFile、HOME兼容drop-in与基线staging。同版SHA重启验收后才能accepted。
5. 批准具体短期STS批次/到期时间、固定实例和aifinance-deploy用户、代理写会话能力、
   有界上传策略及真实操作时限；按已实现编排核对客户端审批清单、真实GitHub构建证据与当前checkout后才能启用。
6. 真实PTY小制品、实际制品吞吐、断线查询/显式resume、健康与回退验收。
   不含迁移/seed/数据回滚、新账号、长期AK、自动续签、公网开放或备案绕过。

## 52.326MiB制品的传输设计评估（未授权、未实现）

上一轮只读核对的代表性tar为54,867,366字节（52.326MiB），本轮没有重新构建或上传该包。
它超过当前客户端1MiB准入，不能用现有代理客户端发布。按768字节stop-and-wait需要
71,442个数据块；现有250ms/往返规划模型约17,876秒，远超480秒。这只是准入计算，
本地PTY吞吐不能证明WAN可行。1MiB限制、LIVE=false和所有远端权限保持不变。

最小可行候选是另行批准仓库已有的forced-command SSH原始stdin upload路径，复用
rebuilt-v1 upload SHA DIGEST、同一摘要检查和artifact-status；不经PTY，不新增下载URL、
分块拼接、通用shell、SCP/SFTP子系统或远端组件。该路径本轮没有获批，当前也没有可用的
备用渠道；仅当管理员确认目标已有合适SSH入口及强制命令隔离时，才值得进入下一轮。
若不存在，停止此候选并另作设计，不能以本建议推导出安装SSH或开放端口的许可。
代理1MiB限制不会因选择此独立入口而扩大。不得把单个大包拆成多次小上传绕过准入。

额外审批与风险：

- 明确允许使用的SSH入口、网络路径、固定主机密钥和短期认证方式；确认现有服务，
  限定部署账号与固定命令，禁PTY/转发/任意shell。不沿用或读取真实凭据作本地测试。
- 审核已有SSH workflow及其执行权限、精确构建SHA/原tar摘要/来源回执、gateway更新摘要，
  保持管理员policy审批、原incoming限额与权限。批准传输不等于批准deploy或restart。
- 管理员验证实际WAN、断线与480秒上传期限；54,867,366字节在480秒内至少需约
  0.915Mbit/s净载荷吞吐，尚未计认证、协议、磁盘/fsync和安全余量，因此不是带宽保证。
  超时失败关闭；本设计不提高期限。无法实测满足则继续阻塞，不默认延长或换通道。
- 断线后先显式artifact-status核对；present=true不可重传，false后也须明确授权同摘要
  的新尝试。部分临时文件、锁、磁盘空间及远端进程须验收；不删除未知现场或自动重放。
- 短期凭据泄露、网络可达性增加、同UID部署隔离较弱及依赖既有SSH配置均须审阅。
  不授予长期AK、新账号、宽泛sudo、任意下载地址或任何数据库写权限。

本候选只省去PTY逐块ACK瓶颈，不证明实机已具备该通道或发布能力。也可由管理员按另批
交付流程放置精确已批准制品，但那仍是独立传输授权，不能被当作当前已有的兜底通道。
网关超时、清理与不确定恢复约束见 [受限发布说明](rebuilt-ecs-deploy.md#网关超时与不确定结果仅代码修复未安装)。
