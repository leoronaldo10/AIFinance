/** Reviewed copy is shared by the website and channel exports. Source evidence stays in the admin. */
export interface FinanceInsight {
  relevance: string;
  scenarios: string[];
  availability: "available" | "limited" | "unknown";
  conditions: string;
  nextStep: string;
  limitations: string;
  evidence: "announcement" | "tested" | "inference";
}

export const AVAILABILITY_LABELS = { available: "可尝试", limited: "有使用条件", unknown: "可用性待核实" } as const;
export const EVIDENCE_LABELS = { announcement: "来源公告／宣称", tested: "有实测依据", inference: "编辑推断" } as const;

export interface EditorialCopy {
  title: string;
  summary: string;
  reason: string;
  category: string | null;
  tags: string[];
  selected: boolean;
  score: number | null;
  finance: FinanceInsight | null;
}

export interface EditorialVersion {
  article_id: string;
  version: number;
  copy: EditorialCopy;
  evidence: { title: string; url: string; text: string; revision: number; analysisId: number | null };
  status: "draft" | "approved" | "rejected";
  actor: string;
  note: string;
  created_at: string;
}

export interface EditorialDetail {
  articleId: string;
  currentVersion: number;
  publishedVersion: number | null;
  withdrawn: boolean;
  versions: EditorialVersion[];
}
