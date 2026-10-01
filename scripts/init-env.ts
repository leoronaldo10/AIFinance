// Creates .env from .env.example with fresh random secrets and an admin password, and prints the password
// once. Refuses to overwrite. --preview writes an independent .env.preview without provider credentials.
// node scripts/init-env.ts [--llm-key <key>] | node scripts/init-env.ts --preview
import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";

const preview = process.argv.includes("--preview");
const output = preview ? ".env.preview" : ".env";
if (preview && process.argv.includes("--llm-key")) throw new Error("预览不接受模型 Key");
if (existsSync(output)) {
  console.error(`${output} 已经存在，没有覆盖。要重新生成，先把它改名或删掉。`);
  process.exit(1);
}
const password = randomBytes(12).toString("base64url");
const keyAt = process.argv.indexOf("--llm-key");
const llmKey = keyAt > 0 ? (process.argv[keyAt + 1] ?? "") : "";
const template = preview ? `# 独立预览；仅由 docker-compose.preview.yml 读取这些白名单变量。
PREVIEW_IMAGE=aifinance-preview:local
PREVIEW_PORT=3100
SITE_URL=http://localhost:3100
ADMIN_PASSWORD=
SESSION_SECRET=
IMG_PROXY_SIGN_SECRET=
POSTGRES_PASSWORD=
` : readFileSync(".env.example", "utf8");
const text = template
  .replace(/^ADMIN_PASSWORD=$/m, `ADMIN_PASSWORD=${password}`)
  .replace(/^SESSION_SECRET=$/m, `SESSION_SECRET=${randomBytes(32).toString("hex")}`)
  .replace(/^IMG_PROXY_SIGN_SECRET=$/m, `IMG_PROXY_SIGN_SECRET=${randomBytes(32).toString("hex")}`)
  .replace(/^POSTGRES_PASSWORD=$/m, `POSTGRES_PASSWORD=${randomBytes(18).toString("hex")}`)
  .replace(/^LLM_API_KEY=$/m, `LLM_API_KEY=${llmKey}`);
writeFileSync(output, text, { mode: 0o600 });
console.log(`已生成 ${output}。`);
console.log(`管理员密码：${password}（也写在 ${output} 的 ADMIN_PASSWORD 里）`);
if (!preview && !llmKey) console.log("还差一步：在 .env 里填上 LLM_API_KEY（以及 LLM_BASE_URL、LLM_MODEL，默认是 DeepSeek）。");
