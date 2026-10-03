import { createElement } from "react";

/** Untrusted feed text is always a React text child, never HTML or Markdown. */
export function RawRssText({ excerpt, body, chars, title }: { title?: string; excerpt?: string | null; body?: string | null; chars?: number }) {
  const text = `${title ?? ""} ${excerpt ?? ""} ${body ?? ""}`;
  const ai = text.match(/\b(?:AI|artificial intelligence|copilot|machine learning|LLM)\b|人工智能|大模型/gi) ?? [];
  const finance = text.match(/\b(?:finance|financial|accounting|accountancy|CFO|audit|ERP)\b|财务|会计|审计/gi) ?? [];
  const hits = (words: string[]) => [...new Set(words.map(w => w.toLowerCase()))].join("、") || "无";
  return createElement("div", null,
    createElement("p", null, `关键词线索（字面匹配，非 AI 筛选）：AI [${hits(ai)}]；财务 [${hits(finance)}]`),
    createElement("p", { className: "mt-4 whitespace-pre-wrap break-words" }, excerpt?.slice(0, 2000) || "RSS 未提供摘要"),
    createElement("pre", { className: "mt-4 max-h-[600px] overflow-auto whitespace-pre-wrap break-words font-sans" }, body?.slice(0, 20000) || "RSS 未提供正文"),
    (chars ?? body?.length ?? 0) >= 20000 ? createElement("p", null, "正文已达 20,000 字符显示上限") : null,
    (excerpt?.length ?? 0) >= 2000 ? createElement("p", null, "摘要已达 2,000 字符显示上限") : null,
  );
}
