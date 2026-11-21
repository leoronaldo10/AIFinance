# 内部采集状态页（只读）

本变更新增原后台的 `/admin/collection-operations` 和受原管理员会话保护的
`GET /api/admin/collection-operations`，只观察固定的 Microsoft Dynamics 365 Finance
信源。没有启用、抓取、预览、重试、分析或发布按钮，也没有新写接口。
网页刷新及可见页面每30秒的更新只执行读取，不会启动模型或任务。

## 能看到什么

- API 读取时间、独立的服务观测时间，均显示北京时间。
- systemd 进程状态和开机启用状态；进程运行不代表抓取成功或业务就绪。
- 来源暂停/启用、原生间隔、下次**可进入调度**的绝对时间。
  暂停时不显示下一次时间；数据过期、服务未知或不可用时也不倒计时或承诺执行。
- 最近20条本信源 fetch_runs：开始/结束、发现、新增、结果及有限错误分类。
  `ok + new_count=0` 是去重后没有新增，不能据此宣布有草稿或发布。
- 无记录、未查到来源、数据库不可用、观测未接入/无效/过期及服务失败分别显示。
  超过30分钟仍未结束的抓取记录显示“实际结果未知”，不伪称成功或自动重试。

不返回 source.config/cursor、URL、正文、标题、actor、audit、原始错误/detail、
日志、DSN、凭据、其他来源或其他付费渠道的数据。SQL 在 READ ONLY 事务中执行，
只对本信源做两个有限 SELECT；SET LOCAL 仅设置事务的3秒 statement_timeout。
沿用编辑身份已有 sources/fetch_runs SELECT，不加数据库权限、表或迁移。

## 私有访问仍是独立发布条件

公网 `aifinops.com.cn` 的 `/admin` 当前被边缘代理404拦截：**保留该规则**，
不得为此页面开放公网后台或例外路径，也不新增公共状态站或公开导出。
原管理员会话/密码/CSRF边界不变；不设置 DEV_AUTH_ROLE，不把管理员 cookie
放进链接、查询串、配置文件、前端或公共产物。

仓库自带的 `scripts/readonly-results` 是历史公开文章的一次性快照导出，
不是实时服务观测，不能拿它或公共 GitHub 日志/产物承载私有状态。

目前没有在本任务中证明可用的私有浏览器入口。历史云浏览器URL策略拒绝仍有效，
不重试、代理或绕过它。新代码完成不代表 Leo 已可从浏览器访问。
发布时只能使用**已获准且实测可用**的私有同源 HTTPS 入口（例如现有私网入口配合
原管理员登录）；若没有，需另行确定并批准私有接入方案。现有公网vhost保持404。
不依赖 Leo 的 Mac，不要求他反复执行日常终端查询。

## 可选被动服务观测

没有可信快照时，页面会明确显示“尚未接入服务观测”，不会从DB记录或旧安装回执
推断服务仍运行。API/Web请求从不执行shell/systemctl、提权、连接云API或触碰worker。

目录 `scripts/collection-observer/`：
`observe.py` 是独立的长期被动进程，每30秒通过固定参数、`shell=False`的默认调用
读取**一个固定systemd单元**的三个非秘密属性，5秒超时。它没有DB/网络/密钥配置，
不读取journald、环境或worker的私有ready文件，不调用start/enable/restart。
失败只写unknown枚举，绝不转录stdout/stderr。完成后原子写一个小JSON快照。

提供的单元是**部署选项，不是本次安装指令**：

- 新代码路径 `/opt/aifinance-collection-observer/observe.py`，管理员提供只读代码。
- 使用既有 `aifinance_editor` OS身份，不能创建、重命名或扩权身份；必须事先核实
  API的有效UID/GID确为同一既有身份。若不符，停止评审，不能chmod现有私密目录兜底。
- 新RuntimeDirectory `/run/aifinance-collection-observer` 为0750，快照0640；
  API需在新发布配置中显式设 `AIHOT_WORKER_STATUS_FILE` 指向该目录的status.json。
  未设置则只显示来源/运行记录和“观测未接入”。
- 无EnvironmentFile、LoadCredential、sudo或capability；ProtectSystem=strict、
  PrivateNetwork、AF_UNIX限制。只需读取现有系统D-Bus属性并写自己的RuntimeDirectory。
  非root固定systemctl属性读取在目标主机是否可行，本轮未实测，不能视为已获权限。
- API只接受root或自身UID拥有、非组/全局可写、非符号链接、最多4096字节的严格六字段
  快照。超过90秒变为stale；错误/未来时间/未知字段不可信，服务状态为未知。
- 该快照只证明三个systemd属性；不能证明worker ready、队列执行、外网抓取或模型成功。

## 版本兼容与范围

实现基于main `50056f08d08d47bf32966b01215169961fee215d`，并单独对部署基线d57
生成保留原审核路由的适配补丁并检查。main补丁不能直接无冲突套到d57；
API仅增加同一个状态页注册，保留d57原有所有审核注册。main与d57的原审核路由/采集隔离实现存在差异，**不得用main整包
替换线上d57/R2**。只评审本提交的小补丁；保留所有已有审核、发布和隔离改动。

未改worker入口、采集器、预算、模型、来源、认证实现、原有后台写操作、公开读取层、
nginx或release链接。新增模块不被worker导入；既有backend源文件保持不变。
应用前仍须用冻结部署manifest检查所有被修改路径是否被worker指纹覆盖；若有覆盖，
必须单独评审新manifest，不能去掉运行时校验。任何部署漂移都停止。

## 验证、发布门槛与回退

本地测试命令（全部合成数据，无真实模型）：

```sh
COLLECT_ENABLED=false MODEL_CALLS_ENABLED=false FEISHU_INTERNAL_ENABLED=false FEISHU_CONTENT_PUSH_ENABLED=false INDEXNOW_SUBMIT_ENABLED=false npm run typecheck
COLLECT_ENABLED=false MODEL_CALLS_ENABLED=false node --test tests/collection-operations.test.ts
python3 -B -m unittest discover -s scripts/collection-observer/tests -v
COLLECT_ENABLED=false MODEL_CALLS_ENABLED=false npm run build -w @aihot/web
COLLECT_ENABLED=false MODEL_CALLS_ENABLED=false node --test apps/web/tests/*.test.ts
```

真实SSR/router测试只启动本机loopback HTTP API替身，不使用任何浏览器、ECS或真实账号。
匿名拒绝通过真实adminHandler测试；授权正向使用明确测试stand-in和SSR合成cookie，
不等于生产管理员会话验收。当前环境没有可用PG17实例，未运行整仓需要空测试库的
不变量套件；新增SQL在真实PG17/R2编辑身份上的权限、RLS及超时仍属独立门槛。
响应式标记和构建通过不等于实际手机像素/触控验收。

上线前独立核实：私有入口/公开404、真实会话过期与no-store、R2补丁与指纹兼容、
既有编辑账号SELECT与D-Bus属性读取、观察服务UID/快照权限、worker仍paused，
以及真实手机/桌面显示。首次启用观测器和API/Web发布/重启须另行批准；
不需要启用信源、试采或调用模型来验收监控页。

配置好入口、观测器与发布后，日常查看/刷新均可在私有浏览器中完成，不再需要ECS终端。
本次没有merge/deploy、启动观察单元、改安全策略或重启API/Web。

回退为撤回本页面/GET路由与导航的小补丁，恢复先前API/Web发布版本和新增状态文件
配置；如果另行安装了观察单元，只停止/禁用**该新观察单元**并撤去它的新代码和
RuntimeDirectory。保留旧release、worker/源开关、数据、预算、审核、历史记录和公网404。
没有数据库迁移、凭据或源数据需要回退；不得借回退执行采集或发布。
