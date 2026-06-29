/**
 * agent.ts — the Sentinel agent, implemented as a Durable Object.
 *
 * Why a Durable Object?
 *   - Each chat session maps to exactly one instance (idFromName(sessionId)),
 *     so we get a private, strongly-consistent place to keep memory.
 *   - The embedded SQLite store holds two things across requests *and* restarts:
 *       • messages  — the running conversation
 *       • cases     — finalized triage findings (the agent's long-term memory)
 *
 * Design: the agent runs a deterministic IOC pipeline (extract → assess → score →
 * recommend) in code so the structured output is always accurate and reproducible,
 * and uses Llama 3.3 on Workers AI for the part that genuinely needs a model — a
 * holistic judgement of the artifact's *content* (urgency, impersonation, social
 * engineering) and a clean analyst summary. The model returns a small JSON object;
 * the code owns everything structured. This is what makes no-IOC phishing get
 * caught and the verdict panel always populated.
 */

import { DurableObject } from "cloudflare:workers";
import { SYSTEM_PROMPT, CLASSIFY_PROMPT } from "./prompts";
import {
  assessIndicator,
  extractIndicators,
  recommendActions,
  scoreAlert,
  type ActionPlan,
  type Category,
  type ExtractedIndicators,
  type IndicatorAssessment,
  type IndicatorType,
  type Severity,
} from "./tools";

export interface Env {
  AI: Ai;
  TRIAGE_AGENT: DurableObjectNamespace<TriageAgent>;
}

const MODEL = "@cf/meta/llama-3.3-70b-instruct-fp8-fast";
const HISTORY_LIMIT = 20; // messages of context fed back to the model

const VERDICTS = ["Malicious", "Suspicious", "Benign", "Needs Review"] as const;
const SEVERITIES: Severity[] = ["Low", "Medium", "High", "Critical"];
const CATEGORIES: Category[] = ["phishing", "malware", "network", "recon", "credential", "other"];

interface Classification {
  is_artifact: boolean;
  verdict: (typeof VERDICTS)[number];
  category: Category;
  severity: Severity;
  title: string;
  summary: string;
  signals: string[];
  user_interaction: boolean;
}

interface ChatMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

export interface SavedCase {
  id: number;
  title: string;
  summary: string;
  severity: string;
  verdict: string;
  indicators: string[];
  recommended_actions: string[];
  created_at: number;
}

export interface ChatResult {
  assistant: string;
  triage: SavedCase | null;
  cases: SavedCase[];
}

export class TriageAgent extends DurableObject<Env> {
  private sql: SqlStorage;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    // Create tables on first touch. blockConcurrencyWhile guarantees no request
    // is served until the schema exists.
    ctx.blockConcurrencyWhile(async () => {
      this.sql.exec(`
        CREATE TABLE IF NOT EXISTS messages (
          id         INTEGER PRIMARY KEY AUTOINCREMENT,
          role       TEXT NOT NULL,
          content    TEXT NOT NULL,
          created_at INTEGER NOT NULL
        );
      `);
      this.sql.exec(`
        CREATE TABLE IF NOT EXISTS cases (
          id                  INTEGER PRIMARY KEY AUTOINCREMENT,
          title               TEXT NOT NULL,
          summary             TEXT NOT NULL,
          severity            TEXT NOT NULL,
          verdict             TEXT NOT NULL,
          indicators          TEXT NOT NULL,
          recommended_actions TEXT NOT NULL,
          created_at          INTEGER NOT NULL
        );
      `);
    });
  }

  /* ----------------------- RPC surface ----------------------- */

  /** Handle one user turn: triage an artifact (or answer a question), and remember it. */
  async chat(userMessage: string): Promise<ChatResult> {
    const text = (userMessage ?? "").trim();
    if (!text) {
      return {
        assistant: "Send an alert, log line, suspicious email, or indicator to triage.",
        triage: null,
        cases: this.listCases(),
      };
    }

    this.persistMessage("user", text);

    // 1. Deterministic IOC pipeline (ground truth — no model involved).
    const ioc = extractIndicators(text);
    const flat = flattenIndicators(ioc);
    const assessments = flat.slice(0, 12).map((f) => assessIndicator(f.value, f.type));
    const high = assessments.filter((a) => a.risk === "high").length;
    const medium = assessments.filter((a) => a.risk === "medium").length;

    // 2. LLM does the holistic judgement of the content, grounded by the IOC findings.
    const c = await this.classify(text, ioc, assessments);

    // Not a security artifact (greeting / general question) → just answer.
    if (!c.is_artifact) {
      const answer = await this.plainChat();
      this.persistMessage("assistant", answer);
      return { assistant: answer, triage: null, cases: this.listCases() };
    }

    // 3. Code owns the structured result.
    const scored = scoreAlert({
      highRiskIndicators: high,
      mediumRiskIndicators: medium,
      userInteraction: c.user_interaction,
      confirmedMalicious: c.verdict === "Malicious",
    });
    const severity = maxSeverity(c.severity, scored.severity);
    const plan = recommendActions(severity, c.category);
    const actions = [...plan.immediate, ...plan.investigation, ...plan.remediation];
    const indicators = [...flat.map((f) => f.value), ...ioc.cves];

    const saved = this.saveCase({
      title: c.title,
      summary: c.summary,
      severity,
      verdict: c.verdict,
      indicators,
      recommended_actions: actions.slice(0, 8),
    });

    const assistant = formatSummary(saved, c.signals, plan);
    this.persistMessage("assistant", assistant);
    return { assistant, triage: saved, cases: this.listCases() };
  }

  /** Restore conversation + case file (used by the UI on page load). */
  async history(): Promise<{ messages: { role: string; content: string }[]; cases: SavedCase[] }> {
    const rows = this.sql
      .exec<{ role: string; content: string }>("SELECT role, content FROM messages ORDER BY id ASC")
      .toArray();
    return { messages: rows, cases: this.listCases() };
  }

  /** Wipe this session. */
  async reset(): Promise<{ ok: true }> {
    this.sql.exec("DELETE FROM messages");
    this.sql.exec("DELETE FROM cases");
    return { ok: true };
  }

  /* ----------------------- model calls ----------------------- */

  private async classify(
    text: string,
    ioc: ExtractedIndicators,
    assessments: IndicatorAssessment[],
  ): Promise<Classification> {
    const grounding =
      `EXTRACTED_INDICATORS: ${JSON.stringify(ioc)}\n` +
      (assessments.length
        ? "HEURISTIC_ASSESSMENTS:\n" +
          assessments.map((a) => `- ${a.indicator} [${a.type}] => ${a.risk} (${a.reasons.join("; ")})`).join("\n")
        : "HEURISTIC_ASSESSMENTS: none");

    const messages: ChatMessage[] = [
      { role: "system", content: CLASSIFY_PROMPT },
      {
        role: "user",
        content: `ARTIFACT TO TRIAGE:\n"""\n${text.slice(0, 6000)}\n"""\n\n${grounding}\n\nRespond with ONLY the JSON object.`,
      },
    ];

    let raw = "";
    try {
      // Prefer JSON mode; fall back to a plain call if the model/endpoint rejects it.
      const res = await this.callAi({ messages, response_format: { type: "json_schema", json_schema: CLASSIFY_SCHEMA } });
      raw = res.response ?? "";
    } catch {
      try {
        const res = await this.callAi({ messages });
        raw = res.response ?? "";
      } catch {
        raw = "";
      }
    }

    return normalizeClassification(parseJsonObject(raw), text, ioc, assessments);
  }

  private async plainChat(): Promise<string> {
    const messages: ChatMessage[] = [
      { role: "system", content: SYSTEM_PROMPT },
      ...this.loadHistoryForModel(),
    ];
    try {
      const res = await this.callAi({ messages });
      return (res.response ?? "").trim() || "I'm Sentinel — paste a security artifact (alert, log, email, or indicator) and I'll triage it.";
    } catch {
      return "I'm Sentinel — paste a security artifact (alert, log, email, or indicator) and I'll triage it.";
    }
  }

  private async callAi(input: Record<string, unknown>): Promise<{ response?: string }> {
    // The typed Ai binding doesn't always know the newest model ids / options,
    // so we narrow to the shape we rely on.
    const ai = this.env.AI as unknown as {
      run(model: string, input: unknown): Promise<{ response?: string }>;
    };
    return ai.run(MODEL, input);
  }

  /* ----------------------- persistence ----------------------- */

  private saveCase(c: {
    title: string;
    summary: string;
    severity: string;
    verdict: string;
    indicators: string[];
    recommended_actions: string[];
  }): SavedCase {
    const now = Date.now();
    const cursor = this.sql.exec<{ id: number }>(
      `INSERT INTO cases (title, summary, severity, verdict, indicators, recommended_actions, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id`,
      c.title,
      c.summary,
      c.severity,
      c.verdict,
      JSON.stringify(c.indicators),
      JSON.stringify(c.recommended_actions),
      now,
    );
    return { id: cursor.one().id, ...c, created_at: now };
  }

  private persistMessage(role: "user" | "assistant", content: string): void {
    this.sql.exec(
      "INSERT INTO messages (role, content, created_at) VALUES (?, ?, ?)",
      role,
      content,
      Date.now(),
    );
  }

  private loadHistoryForModel(): ChatMessage[] {
    const rows = this.sql
      .exec<{ role: string; content: string }>(
        "SELECT role, content FROM messages ORDER BY id DESC LIMIT ?",
        HISTORY_LIMIT,
      )
      .toArray()
      .reverse();
    return rows
      .filter((r) => r.role === "user" || r.role === "assistant")
      .map((r) => ({ role: r.role as ChatMessage["role"], content: r.content }));
  }

  private listCases(): SavedCase[] {
    return this.sql
      .exec<{
        id: number;
        title: string;
        summary: string;
        severity: string;
        verdict: string;
        indicators: string;
        recommended_actions: string;
        created_at: number;
      }>("SELECT * FROM cases ORDER BY id DESC LIMIT 50")
      .toArray()
      .map((r) => ({
        id: r.id,
        title: r.title,
        summary: r.summary,
        severity: r.severity,
        verdict: r.verdict,
        indicators: safeParseArray(r.indicators),
        recommended_actions: safeParseArray(r.recommended_actions),
        created_at: r.created_at,
      }));
  }
}

/* ----------------------- module helpers ----------------------- */

const CLASSIFY_SCHEMA = {
  type: "object",
  properties: {
    is_artifact: { type: "boolean" },
    verdict: { type: "string", enum: VERDICTS },
    category: { type: "string", enum: CATEGORIES },
    severity: { type: "string", enum: SEVERITIES },
    title: { type: "string" },
    summary: { type: "string" },
    signals: { type: "array", items: { type: "string" } },
    user_interaction: { type: "boolean" },
  },
  required: ["is_artifact", "verdict", "category", "severity", "title", "summary", "signals"],
} as const;

function flattenIndicators(ioc: ExtractedIndicators): { value: string; type: IndicatorType }[] {
  const out: { value: string; type: IndicatorType }[] = [];
  for (const u of ioc.urls) out.push({ value: u, type: "url" });
  for (const d of ioc.domains) out.push({ value: d, type: "domain" });
  for (const ip of ioc.ipv4) out.push({ value: ip, type: "ip" });
  for (const e of ioc.emails) out.push({ value: e, type: "email" });
  for (const h of ioc.hashes) out.push({ value: h, type: "hash" });
  return out;
}

function maxSeverity(a: Severity, b: Severity): Severity {
  return SEVERITIES.indexOf(a) >= SEVERITIES.indexOf(b) ? a : b;
}

function deriveTitle(text: string): string {
  const firstLine = text.split("\n").map((l) => l.trim()).find((l) => l.length > 0) ?? "Security triage";
  return firstLine.slice(0, 70);
}

function deriveSignals(assessments: IndicatorAssessment[]): string[] {
  const reasons = assessments
    .filter((a) => a.risk === "high" || a.risk === "medium")
    .flatMap((a) => a.reasons);
  return reasons.length ? [...new Set(reasons)].slice(0, 4) : ["No technical IOCs extracted — assessed on message content and context."];
}

function normalizeClassification(
  parsed: Record<string, unknown>,
  text: string,
  ioc: ExtractedIndicators,
  assessments: IndicatorAssessment[],
): Classification {
  const high = assessments.filter((a) => a.risk === "high").length;
  const hasIoc = ioc.count > 0;
  const fallbackArtifact = hasIoc || text.length > 40 || text.includes("\n");

  const verdict = (VERDICTS as readonly string[]).includes(String(parsed.verdict))
    ? (parsed.verdict as Classification["verdict"])
    : high > 0
      ? "Suspicious"
      : "Needs Review";

  const severity = SEVERITIES.includes(parsed.severity as Severity)
    ? (parsed.severity as Severity)
    : high > 0
      ? "High"
      : hasIoc
        ? "Medium"
        : "Low";

  const category = CATEGORIES.includes(parsed.category as Category)
    ? (parsed.category as Category)
    : "other";

  const title =
    typeof parsed.title === "string" && parsed.title.trim()
      ? parsed.title.trim().slice(0, 80)
      : deriveTitle(text);

  const summary =
    typeof parsed.summary === "string" && parsed.summary.trim()
      ? parsed.summary.trim()
      : `Heuristic triage of the submitted artifact (${ioc.count} indicator(s) found).`;

  const signals =
    Array.isArray(parsed.signals) && parsed.signals.length
      ? parsed.signals.map(String).slice(0, 5)
      : deriveSignals(assessments);

  return {
    is_artifact: typeof parsed.is_artifact === "boolean" ? parsed.is_artifact : fallbackArtifact,
    verdict,
    category,
    severity,
    title,
    summary,
    signals,
    user_interaction: typeof parsed.user_interaction === "boolean" ? parsed.user_interaction : false,
  };
}

function formatSummary(saved: SavedCase, signals: string[], plan: ActionPlan): string {
  const why = (signals.length ? signals : ["Assessed on content and context."]).slice(0, 4);
  const next = [...plan.immediate, ...plan.investigation].slice(0, 3);
  const lines = [
    `**Verdict: ${saved.verdict} · Severity: ${saved.severity}**`,
    "",
    saved.summary,
    "",
    "**Why:**",
    ...why.map((s) => `- ${s}`),
    "",
    "**Do next:**",
    ...next.map((s) => `- ${s}`),
  ];
  if (saved.indicators.length) {
    lines.push("", `_${saved.indicators.length} indicator(s) saved to the case file._`);
  }
  return lines.join("\n");
}

function parseJsonObject(raw: unknown): Record<string, unknown> {
  if (raw && typeof raw === "object") return raw as Record<string, unknown>;
  if (typeof raw !== "string" || !raw.trim()) return {};
  try {
    return JSON.parse(raw) as Record<string, unknown>;
  } catch {
    const s = raw.indexOf("{");
    const e = raw.lastIndexOf("}");
    if (s >= 0 && e > s) {
      try {
        return JSON.parse(raw.slice(s, e + 1)) as Record<string, unknown>;
      } catch {
        /* fall through */
      }
    }
    return {};
  }
}

function safeParseArray(raw: string): string[] {
  try {
    const v = JSON.parse(raw);
    return Array.isArray(v) ? v.map(String) : [];
  } catch {
    return [];
  }
}
