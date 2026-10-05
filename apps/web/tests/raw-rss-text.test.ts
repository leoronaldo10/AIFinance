import assert from "node:assert/strict";
import { test } from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { RawRssText } from "../app/features/admin/raw-rss-text.ts";

test("RSS script, image and link payloads render only as bounded text", () => {
  const payload = '<script>alert(1)</script><img src="https://example.com/track" onerror="alert(1)"><a href="javascript:alert(1)">click</a>';
  const html = renderToStaticMarkup(createElement(RawRssText, { excerpt: payload, body: payload + "x".repeat(25000) }));
  assert.ok(html.includes('&lt;script&gt;'));
  assert.ok(html.includes('&lt;img'));
  assert.ok(!/<script|<img|<a\b/.test(html));
  assert.ok(html.includes('正文已达 20,000 字符显示上限'));
  assert.ok(html.length < 21000);
});


test("keyword clues expose literal AI and finance matches without claiming classification", () => {
  const html = renderToStaticMarkup(createElement(RawRssText, { title: "Copilot for CFO accounting", body: "Public RSS text" }));
  assert.ok(html.includes("AI [copilot]"));
  assert.ok(html.includes("财务 [cfo、accounting]"));
  assert.ok(html.includes("字面匹配，非 AI 筛选"));
});
