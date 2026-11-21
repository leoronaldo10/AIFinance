import { useEffect, useState } from "react";
import { data as routeData, useRevalidator } from "react-router";
import { SITE } from "@aihot/industry/site";
import type { CollectionOperations } from "@aihot/contracts/collection-operations";
import type { Route } from "./+types/collection-operations";
import { adminGet } from "../../lib/admin.server";
import { CollectionOperationsView } from "../../features/admin/collection-operations";
export async function loader({ request }: Route.LoaderArgs) {
  try {
    const status = await adminGet<CollectionOperations>(request, "/api/admin/collection-operations");
    return { status, renderedAt: Date.now() };
  } catch (error) {
    if (error instanceof Response && error.status >= 300 && error.status < 400) throw error;
    // Loader errors are serialized for hydration: sanitize here, not only in ErrorBoundary.
    throw routeData({ message: "采集状态暂不可用" }, { status: 503 });
  }
}
export const meta: Route.MetaFunction = () => [{ title: `采集状态（只读） · ${SITE.name} 后台` }, { name: "robots", content: "noindex, nofollow" }];
export const headers: Route.HeadersFunction = () => ({ "Cache-Control": "no-store", "X-Robots-Tag": "noindex, nofollow" });
export default function CollectionOperationsPage({ loaderData }: Route.ComponentProps) {
  const revalidator = useRevalidator();
  const [clock, setClock] = useState<number | null>(null);
  useEffect(() => {
    const timer = setInterval(() => setClock(Date.now()), 15_000);
    setClock(Date.now());
    return () => clearInterval(timer);
  }, []);
  useEffect(() => {
    const refresh = () => { if (document.visibilityState === "visible" && revalidator.state === "idle") void revalidator.revalidate(); };
    const timer = setInterval(refresh, 30_000);
    document.addEventListener("visibilitychange", refresh);
    return () => { clearInterval(timer); document.removeEventListener("visibilitychange", refresh); };
  }, [revalidator]);
  return <CollectionOperationsView data={loaderData.status} now={clock ?? loaderData.renderedAt} refreshing={revalidator.state !== "idle"} onRefresh={() => void revalidator.revalidate()} />;
}
export function ErrorBoundary() {
  return <section className="m-4 max-w-xl rounded-control border border-line bg-surface p-5" role="alert"><h1 className="text-lg font-semibold">采集状态暂不可用</h1><p className="mt-2">连接失败或登录已过期。当前运行状态未知，不能将之前的成功记录视为最新状态。</p><a className="mt-4 inline-block underline" href="/admin/collection-operations">重新读取状态</a></section>;
}
