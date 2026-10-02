# 公开来源检查记录（2026-10-02 UTC）

仅检查公开RSS/搜索索引，没有请求付费正文、登录或绕过403，没有生产写入。三个配置URL仍保持原样、默认disabled。

| 配置源 | 本次直接运行受审 fetchRss(publicTextOnly) | 本环境HTTPS代理 | 浏览工具打开RSS |
|---|---|---|---|
| [Dynamics 365 Finance RSS](https://www.microsoft.com/en-us/dynamics-365/blog/product/dynamics-365-finance/feed/) | DNS EAI_AGAIN | CONNECT 403 | 上游/robots连接超时 |
| [Journal of Accountancy RSS](https://www.journalofaccountancy.com/news/feed/) | DNS EAI_AGAIN | CONNECT 403 | 报告application/rss+xml不支持 |
| [Accounting Today RSS](https://www.accountingtoday.com/feed?rss=true) | DNS EAI_AGAIN | CONNECT 403 | 报告application/xml不支持 |

结论：**本次不能独立确认HTTP200、XML条目数或当前RSS正文样例**。这些结果不能证明源站失效，也不能用于批准生产外联。此前父线程报告过三个HTTP200可parse；本记录没有把它当作本次结果。不存在拿搜索索引替代真实RSS验收的情况。下一次由已批准出口只请求原RSS并记录HTTP状态/最终URL/条目数/有界文本长度；遇403停止，不改UA绕过、不接正文provider。

本次搜索索引可见以下与范围相关的标题，作为**题材参考，未证实仍在当前RSS或将被首批采到**：

- Microsoft 官方 [AI主题页](https://www.microsoft.com/en-us/dynamics-365/blog/topic/ai/page/2/) 索引标题 “Moving sales, service, and finance to the Frontier with Microsoft 365 Copilot”。这是产品与财务职能结合的内容线索。
- Journal of Accountancy [2026年7月报道](https://www.journalofaccountancy.com/news/2026/jul/are-finance-leaders-moving-too-fast-on-agentic-ai/) 标题 “Are finance leaders moving too fast on agentic AI?”，索引涉及财务领导者的AI投资回报与治理压力。
- Accounting Today [报道](https://www.accountingtoday.com/news/cfos-spending-heavily-on-ai) 标题 “CFOs spending heavily on AI”，索引显示2026-09-30发布，涉及财务负责人对AI投入的担忧；未请求其付费正文。

源码测试证明：真实本地HTTP RSS→PostgreSQL解析/去重、整批≤3、保留短摘要、无正文页/图片请求、同源跳转/SSRF拒绝、下游零新增。它们不能代替当前外部RSS或生产网络验收。当前无需改来源表，也不宣称已用AI筛选。
