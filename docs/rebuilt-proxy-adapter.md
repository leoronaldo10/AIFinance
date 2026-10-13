# 固定代理发布适配：仅离线/mock

2026-10-13：基于 ed05b485 的 reviewed readonly-proxy-v3 原样来源实现。
没有读取 STS、调用云 API、建立外部 WebSocket、访问 ECS 或改变服务器。
readonly client 的 LIVE=false、来源和校验清单不变。旧 SSH workflow 不变。

## 已实现的边界

`deploy/native/rebuilt-proxy.py` 是离线库，不是可运行的远程发布器。
connection_plan 复用审查版 require_proxy、TLS验证、canonical query 和 ACS3签名；
只生成内存计划，不发送请求。凭据与 expiration 必须显式传入，不能从环境读取，
不使用只读源码里的历史 expiration。计划包含秘密，调用方不得打印或保存。
require_proxy 强制已有环境代理（NO_PROXY 不形成绕过）；证书与主机名验证保持开启。
已审查的 API connection、session URL/token 检查和 WebSocket connector 仍在原文件，
本轮没有把它们连接成 live 发布入口。connect_live 无条件拒绝；没有开启开关。

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

客户端在首帧前核对bytes大小、SHA256及显式构建来源记录：固定仓库、完整revision、
sha256、checks_passed、build_run。该记录是调用方提供的审核证据，不是加密签名证明；
以后live准入必须独立核验构建run与批准SHA/摘要，不能凭自报字段授权。
发布/回退绑定32hex operation ID；上传由SHA/摘要识别，不冒充发布回执。

上传断线后显式调用固定 `artifact-status SHA DIGEST`：持共享锁、验证policy批准配对，
核对incoming文件真实摘要；present=true确认已提交，false仅表示查询时无完整制品。
竞争上传可能使锁拒绝；停止等待人工选择后续查询，不自动重传。SHA同名异摘要失败关闭。
发布断线用status ID核对既有回执，再由调用方明确选择resume ID；保持原ID和原制品。
不删除回执，不自动恢复recovery_required，不自动发起新operation。

离线exchange使用Unix主线程专用SIGALRM总时限（1..480秒测试参数），覆盖recv与阻塞send，
保留恢复原信号handler，已有timer则拒绝；服务器原480秒alarm不变。
这不是获批的真实上传/操作时间。768字节stop-and-wait上传128MiB需要174,763次往返，
480秒要求平均RTT低于2.75ms，实际代理大制品很可能超时。因此当前方案只证明有界、安全
失败及小制品传输，不承诺最大制品可完成。真实批准前须按实际制品大小制定并离线验证
有界窗口/流控/时限方案，再另批真实测试；不能简单延长期限或忽略ACK。

## 验证与审批

`npm run test:rebuilt` 纳入适配14项：本地真实默认PTY的任意binary字节往返、坏输入、
摘要/来源、代理/TLS、错误版本/通道/序号、重复ACK、断线、阻塞发送时限、固定请求、
真实网关upload/artifact-status、受限解包/deploy、status与显式resume、重复操作无重启。
主机systemd/HTTP由既有fixture替代，真实发布状态机、临时文件/链接/回执和解包器参与。
来源原70项及SHA256清单亦已本地重跑。没有ECS实测，没有API发送集成或远程吞吐验收。

后续一次性服务器落地审批清单（本轮不申请、不执行）：

1. 明确实际首发SHA/制品摘要/构建run/operation ID、可信回退SHA、维护与回退窗口。
2. 审查并安装root管理gateway（含terminal入口）、extractor、launcher、policy v2，
   文件摘要以更新后的rebuilt-release-files.sha256为准；必要时同步bootstrap摘要。
3. 审核incoming/releases/state/rebuilt及switch最小写权限，不递归chown；同UID不强隔离。
4. 两个95启动drop-in、精确sudo联合restart、管理员daemon-reload及失败恢复步骤；
   保留原EnvFile、HOME兼容drop-in与基线staging。同版SHA重启验收后才能accepted。
5. 批准具体短期STS批次/到期时间、固定实例和aifinance-deploy用户、代理写会话能力、
   有界上传策略及真实操作时限；审查live API编排和构建来源核验后才能启用。
6. 真实PTY小制品、实际制品吞吐、断线查询/显式resume、健康与回退验收。
   不含迁移/seed/数据回滚、新账号、长期AK、自动续签、公网开放或备案绕过。
