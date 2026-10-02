# 部署

本仓库是 `leoronaldo10/AIFinance`。财务编辑功能目前位于 PR #1 的 `feat/finance-editorial-workflow`；不要克隆上游 AIHOT，也不要把 main 当作已包含本 PR。上线前核对实际提交、CI 和审阅结果。

没有 Docker 的 Alibaba Cloud Linux ECS 可先审阅[原生预览与 GitHub Actions 准备方案](native-deploy.md)；它需要独立的 systemd 网络隔离验收，不可直接套用下面的 Docker 保证。

## 隔离预览（2 核 / 2 GiB 机器优先使用）

预览用于手动导入演示材料、编辑、审核和出稿，不启用真实采集、模型或通知。它使用独立数据库和卷，不连接旧站数据。**此流程不是正式生产部署。**

在内存充足的云端构建机上获取已审阅代码（构建仍需要访问镜像与 npm 仓库）：

```bash
git clone --branch feat/finance-editorial-workflow https://github.com/leoronaldo10/AIFinance.git aifinance
cd aifinance
git rev-parse HEAD  # 必须与本次审阅通过的提交一致；后续分支更新需重新验证
npm ci
npm run typecheck
npm run test:preview
npm run build -w @aihot/web
node --test apps/web/tests/*.test.ts
docker build -t aifinance-preview:local .
```

生产镜像验证还需要独立 PostgreSQL 上的后端测试和迁移/冒烟，见 [finance-editorial.md](finance-editorial.md)。通过后把镜像传到目标机器，使用明确版本标签或 digest 设置 `PREVIEW_IMAGE`；不要在 2 GiB ECS 上默认执行镜像构建。镜像传输、拉取和构建不属于运行期断网保证。

在预览目录生成独立凭据，不需要模型 Key：

```bash
node scripts/init-env.ts --preview
# 编辑 .env.preview：PREVIEW_IMAGE 改为刚验证的镜像，SITE_URL 改为实际预览入口。
docker compose --env-file .env.preview -f docker-compose.preview.yml config --quiet
docker compose --env-file .env.preview -f docker-compose.preview.yml up -d --no-build
```

不要与 `docker-compose.yml` 叠加使用；也不要去掉 `--env-file .env.preview`。此配置只有 db、setup、api、web；setup 仅迁移独立预览库和初始化主题，不导入示范源。所有应用变量采用白名单，不加载生产 `.env`、模型 Key、飞书、采集服务或对象存储凭据。

安全边界：

- 运行容器只加入 Docker `internal` 网络，应用没有外网路由；没有 worker。`PREVIEW_MODE=true` 额外禁止 worker 启动、模型/推送/IndexNow，以及统一 HTTP 抓取入口（含信源试抓和图片代理）。不要接入其他网络、代理或挂载生产凭据。内部网络不是针对容器逃逸或宿主机服务的沙箱，仍保留原 SSRF 防护。
- 浏览器响应增加 CSP，禁止外站图片、脚本、嵌入和连接；设置 noindex。读者主动点击原文仍会离开本站。后台试抓在预览中失败是预期行为，外部图片不可用；使用文字演示材料和本地资源。
- 只发布 `127.0.0.1:3100`，数据库和 API 不映射宿主机端口。手机查看需由宿主机现有 HTTPS 反向代理转发到此地址；TLS 终止放在隔离网络外。域名、证书及现存端口需先核实，不能直接开放 HTTP 管理员登录。
- 配置使用生产模式与管理员密码，禁止开发免登录。不要共享管理员密码。默认不信任转发 IP（限流按代理地址聚合）；noindex 不等于访问控制，若预览需私密，须在反向代理另设访问认证。
- db / api / web 内存上限分别为 384 / 384 / 512 MiB；setup 上限 384 MiB，完成后才启动应用。这只是小规模预览的初始限制，不是 2 GiB 容量保证；必须验证实际内存、磁盘和并发，给 OS 与反向代理留余量。

首次启动后核查 `docker compose ... ps` 只有上述服务；跑健康检查、管理员登录、导入→审核→公开→撤回与手机页面验收。还应验证容器出站请求失败。未通过这些运行期检查不能认定安全预览已可用。停止时仍使用同一 `--env-file` 和 `-f`；`down` 保留数据，`down -v` 删除预览数据，不要误用于生产项目。

## 旧站升级的额外门槛

0039 会撤下全部已有公开文章并移除精选；0040 与 seed 更新当前主题。回填审核队列在 SQL 迁移提交后逐篇进行，须用数据副本演练耗时和失败恢复。备份并验证可恢复后再安排维护窗口，停止旧 worker，核查已有启用信源与积压任务。`sources.json` 的 disabled 不会覆盖数据库状态。旧内容需重新审核；只回滚应用镜像不会恢复旧公开状态。不要把已有生产数据库直接用于预览。

## 正式生产部署（确认采集、预算和内容策略后）

需要一台装了 Docker（带 Compose）的机器。云服务器建议至少 2 核、4 GB 内存，构建镜像时要用到。

```bash
git clone --branch feat/finance-editorial-workflow https://github.com/leoronaldo10/AIFinance.git aifinance
cd aifinance
git rev-parse HEAD  # 核对已审阅提交
node scripts/init-env.ts --llm-key <你的模型 API Key>
docker compose up -d --build
```

`init-env.ts` 会生成 `.env`，填好随机密钥和管理员密码，并把密码打印一次。机器上没有 Node 的话，把 `.env.example` 复制成 `.env`，自己填 `ADMIN_PASSWORD`（至少 12 位）、`SESSION_SECRET`、`IMG_PROXY_SIGN_SECRET`、`POSTGRES_PASSWORD`（各用 `openssl rand -hex 32` 生成）和 `LLM_API_KEY`。

默认 Compose 包含 worker；`.env.example` 的采集和模型开关默认开启。仅在明确启用自动化时使用，先配置预算和核实信源。财务版示范源默认关闭，内容必须审核后才公开，不会启动后自动出新闻。管理员登录前必须先配置下面的 HTTPS；不要经公网 HTTP 传输密码。

`docker compose` 会起五个容器：`db`（PostgreSQL 17）、`setup`（每次启动先跑数据库迁移和种子数据，然后退出）、`api`、`worker`（抓取、模型处理、定时任务）、`web`（网页）。

### 在中国大陆的服务器上

- 构建时 npm 走国内镜像：`docker compose build --build-arg NPM_REGISTRY=https://registry.npmmirror.com`，然后 `docker compose up -d`。
- 拉取 Docker 镜像慢，先给 Docker 配置镜像加速。
- 海外信源抓不到时，在 `.env` 里设置 `EGRESS_PROXY_URL`：抓信源、图片和模型榜数据时走这个代理，调用模型接口不走。
- 对外提供网站服务需要先完成 ICP 备案，备案号填在 `industry/site.ts` 的 `icp`。

### 配域名和 HTTPS

先把域名解析到服务器，然后在 `.env` 里设置：

```bash
SITE_URL=https://example.com
SITE_DOMAIN=example.com
PORT=127.0.0.1:3000        # 3000 端口只给本机的 Caddy 用，不直接对外
TRUST_PROXY=true           # 访客地址从 Caddy 转来的请求头里读
```

再用带 HTTPS 的方式启动，Caddy 会自动申请和续期证书：

```bash
docker compose --profile https up -d --build
```

已经有 Nginx 的话，不用 Caddy，把站点反向代理到 `http://127.0.0.1:3000`，带上 `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`，并在 `.env` 里设 `TRUST_PROXY=true`。`SITE_URL` 一定要写成读者实际访问的地址：生成的链接、RSS、分享图和 MCP 都用它。

### 更新

```bash
git pull
docker compose up -d --build
```

更新会自动执行迁移。0039 存在上文所述内容可见性变化，不可按无影响更新处理；每次更新均核对新提交与迁移。

### 备份

在 `.env` 里配置 `DB_BACKUP_STORE_*`（任何 S3 兼容的对象存储），每天 04:10 自动备份到那里。也可以手动导出：

```bash
docker compose exec -T db pg_dump -U aihot aihot | gzip > myhot-$(date +%F).sql.gz
```

数据都在三个 Docker 卷里：`db`（数据库）、`data`（上传的图片、图片缓存、本地备份）、`caddy`（证书）。`docker compose down` 不会删除它们；`docker compose down -v` 会。

### 看日志

```bash
docker compose logs -f --tail 100 api worker web
```

后台的“运行”页能看到每个定时任务最近的结果，“信源”页能看到每个信源的抓取状况。

## 花多少钱

- **模型**：每条新资料至少预筛一次；可能入选的再评分两次，入选的还要写标题摘要、打标签、归组，另外还有日报和事件综述。我们用示范信源在本地试跑，第一次导入的 152 条资料一共用了大约 930 次模型调用。之后每天用多少，取决于你的信源每天更新多少条。后台“模型与评测”页能看到每一步的调用次数和输入输出 token 数。
- **付费采集**（X、公众号、Jina）：按请求计费，默认不启用，填了 key 才会用。
- 所有付费服务都有每分钟、每小时、每天的调用上限（后台“设置 → 预算”），超过就暂停，不会一夜之间刷爆账单。填 0 表示立即停用这个服务。

## 不用 Docker

需要 Node.js 24.11 以上和 PostgreSQL 16 或 17。

```bash
npm ci
node scripts/init-env.ts --llm-key <你的模型 API Key>
createdb myhot
```

在 `.env` 里加上：

```bash
DATABASE_URL=postgres://你的用户名@127.0.0.1:5432/myhot
API_BASE_URL=http://127.0.0.1:3001
```

然后：

```bash
node --env-file=.env scripts/migrate.ts
node --env-file=.env scripts/seed.ts
npm run build -w @aihot/web

node --env-file=.env apps/api/src/main.ts          # 接口，3001 端口
node --env-file=.env apps/worker/src/main.ts       # 后台任务
cd apps/web && NODE_ENV=production node --env-file=../../.env server.ts   # 网页，3000 端口
```

三个进程要一直运行，生产环境用 systemd 或 pm2 守护。

开发时用带热更新的方式：`npm run dev:api`、`npm run dev:worker`、`npm run dev:web`。开发时想免登录进后台，在 `.env` 里设 `DEV_AUTH_ROLE=admin`（生产环境会拒绝启动）。
