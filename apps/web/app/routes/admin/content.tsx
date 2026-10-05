import { SITE } from "@aihot/industry/site";
import { Form, Link, useNavigate, useSearchParams } from "react-router";
import type { Route } from "./+types/content";
import { adminGet } from "../../lib/admin.server";
import { VISIBILITY_LABEL } from "../../features/admin/labels";
import { AdminPage, Badge, Button, Card, DataTable, Input, Time } from "../../features/admin/ui";

interface Row {
  id: string;
  title: string;
  url: string;
  source: string;
  discovered_at: string;
  processing_state: string;
  participation_mode: string;
  collect_only: boolean;
  visibility: string | null;
  selected: boolean | null;
  score: number | null;
}

export async function loader({ request }: Route.LoaderArgs) {
  const q = new URL(request.url).searchParams.get("q")?.trim() ?? "";
  const { rows } = await adminGet<{ rows: Row[] }>(request, `/api/admin/content?q=${encodeURIComponent(q)}`);
  return { q, rows };
}

export const meta: Route.MetaFunction = () => [{ title: `内容诊断 · ${SITE.name} 后台` }];

export default function Content({ loaderData }: Route.ComponentProps) {
  const { q, rows } = loaderData;
  const [sp] = useSearchParams();
  const navigate = useNavigate();
  return (
    <AdminPage title="内容诊断" subtitle="最近内容的原始标题；标记“原始候选”的仅采集内容未经 AI 筛选。可按标题关键词、ID 或原文链接查找。">
      <Form method="get" className="mb-5 flex max-w-2xl gap-2">
        <Input name="q" defaultValue={sp.get("q") ?? ""} placeholder="内容 ID、URL 或标题关键词" aria-label="搜索内容" autoFocus />
        <Button type="submit" tone="primary">查找</Button>
      </Form>
      {(
        <Card pad={false} title={q ? `“${q}” 的结果` : "最近采集（最多 50 条）"} right={<span>{rows.length === 50 ? "仅显示最近 50 条" : `${rows.length} 条`}</span>}>
          <DataTable
            rows={rows}
            rowKey={(r) => r.id}
            onRowClick={(r) => navigate(`/admin/content/${r.id}`)}
            empty="没有找到。URL 会先规范化再比对；标题支持中英文片段。"
            columns={[
              {
                key: "t",
                label: "标题",
                render: (r) => (
                  <div className="min-w-[320px]">
                    <Link to={`/admin/content/${r.id}`} className="font-medium text-ink hover:text-accent" onClick={(e) => e.stopPropagation()}>{r.title}</Link>
                    <a href={/^https?:\/\//i.test(r.url) ? r.url : undefined} target="_blank" rel="noreferrer" className="block max-w-lg truncate text-[11.5px] text-ink-4" onClick={(e) => e.stopPropagation()}>{r.url}</a>
                  </div>
                ),
              },
              { key: "src", label: "信源", render: (r) => <span className="whitespace-nowrap">{r.source}</span> },
              {
                key: "st",
                label: "状态",
                render: (r) => (
                  <span className="flex flex-wrap gap-1">
                    {r.selected && <Badge tone="accent">精选</Badge>}
                    {r.visibility && <Badge tone={r.visibility === "public" ? "muted" : "warn"}>{VISIBILITY_LABEL[r.visibility] ?? r.visibility}</Badge>}
                    {!r.visibility && <Badge>{r.collect_only ? "原始候选" : r.processing_state}</Badge>}
                  </span>
                ),
              },
              { key: "sc", label: "分数", align: "right", render: (r) => r.score ?? "—" },
              { key: "d", label: "发现", render: (r) => <Time at={r.discovered_at} /> },
            ]}
          />
        </Card>
      )}
    </AdminPage>
  );
}
