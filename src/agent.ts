/**
 * agent.ts — the Sentinel agent, implemented as a Durable Object.
 *
 * Why a Durable Object?
 *   - Each chat session maps to exactly one instance (idFromName(sessionId)),
 *     so we get a private, strongly-consistent place to keep memory.
 *   - The embedded SQLite store holds two things across requests *and* restarts:
 *       • messages  — the running conversation
 *       • cases     — finalized triage findings the agent chooses to remember
 *   - The agent loop (LLM → tool → LLM → …) runs here, close to its state.
 *
 * The LLM is Llama 3.3 on Workers AI, driven with native function calling.
 */

import { DurableObject } from "cloudflare:workers";
import { SYSTEM_PROMPT } from "./prompts";
import {
  assessIndicator,
  extractIndicators,
  recommendActions,
  scoreAlert,
  toolDefinitions,
  type IndicatorType,
  type Severity,
  type Category,
} from "./tools";

export interface Env {
  AI: Ai;
  TRIAGE_AGENT: DurableObjectNamespace<TriageAgent>;
}

const MODEL = "@cf/meta/llama-3.3-70b-instruct-fp8-fast";
const MAX_TOOL_STEPS = 8; // safety cap on the agent loop
const HISTORY_LIMIT = 20; // messages of context fed back to the model

/* ---- shapes exchanged with the model / client ---- */

interface AiToolCall {
  name: string;
  arguments: Record<string, unknown> | string;
}
interface AiRunResult {
  response?: string;
  tool_calls?: AiToolCall[];
}
interface ChatMessage {
  role: "system" | "user" | "assistant" | "tool";
  content: string;
  name?: string;
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

  /** Handle one user turn: persist it, run the agent loop, persist the reply. */
  async chat(userMessage: string): Promise<ChatResult> {
    const text = (userMessage ?? "").trim();
    if (!text) {
      return { assistant: "Send an alert, log line, suspicious email, or indicator to triage.", triage: null, cases: this.listCases() };
    }

    this.persistMessage("user", text);

    const messages: ChatMessage[] = [
      { role: "system", content: SYSTEM_PROMPT },
      ...this.loadHistoryForModel(),
    ];

    const { assistantText, triage } = await this.runAgentLoop(messages);
    this.persistMessage("assistant", assistantText);

    return { assistant: assistantText, triage, cases: this.listCases() };
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

  /* ----------------------- agent loop ----------------------- */

  private async runAgentLoop(
    messages: ChatMessage[],
  ): Promise<{ assistantText: string; triage: SavedCase | null }> {
    let triage: SavedCase | null = null;

    for (let step = 0; step < MAX_TOOL_STEPS; step++) {
      const result = await this.callModel(messages);
      const toolCalls = result.tool_calls ?? [];

      if (toolCalls.length === 0) {
        const text = (result.response ?? "").trim();
        return { assistantText: text || "Triage complete.", triage };
      }

      for (const call of toolCalls) {
        const args = parseArgs(call.arguments);
        const toolResult = this.dispatchTool(call.name, args);
        if (call.name === "save_case_note" && toolResult.case) {
          triage = toolResult.case;
        }
        // Feed the call + its result back so the model can continue reasoning.
        messages.push({ role: "assistant", content: JSON.stringify({ name: call.name, arguments: args }) });
        messages.push({ role: "tool", name: call.name, content: JSON.stringify(toolResult) });
      }
    }

    // Hit the step cap — ask for a final summary with tools disabled.
    const wrap = await this.callModel(
      [...messages, { role: "user", content: "Summarize your triage now. Do not call any more tools." }],
      false,
    );
    return { assistantText: (wrap.response ?? "Triage complete.").trim(), triage };
  }

  private async callModel(messages: ChatMessage[], withTools = true): Promise<AiRunResult> {
    // The typed Ai binding doesn't always know about the newest model ids / the
    // tools option, so we narrow to the shape we actually rely on.
    const ai = this.env.AI as unknown as {
      run(model: string, input: unknown): Promise<AiRunResult>;
    };
    const input: Record<string, unknown> = { messages };
    if (withTools) input.tools = toolDefinitions;
    return ai.run(MODEL, input);
  }

  /* ----------------------- tool dispatch ----------------------- */

  private dispatchTool(name: string, args: Record<string, unknown>): { case?: SavedCase; [k: string]: unknown } {
    switch (name) {
      case "extract_indicators":
        return { result: extractIndicators(String(args.text ?? "")) };
      case "assess_indicator":
        return {
          result: assessIndicator(String(args.indicator ?? ""), (args.type as IndicatorType) ?? "domain"),
        };
      case "score_alert":
        return {
          result: scoreAlert({
            highRiskIndicators: Number(args.highRiskIndicators ?? 0),
            mediumRiskIndicators: Number(args.mediumRiskIndicators ?? 0),
            affectsCriticalAsset: Boolean(args.affectsCriticalAsset),
            confirmedMalicious: Boolean(args.confirmedMalicious),
            userInteraction: Boolean(args.userInteraction),
            signals: Array.isArray(args.signals) ? (args.signals as string[]) : [],
          }),
        };
      case "recommend_actions":
        return {
          result: recommendActions(
            (args.severity as Severity) ?? "Low",
            (args.category as Category) ?? "other",
          ),
        };
      case "save_case_note":
        return { case: this.saveCase(args) };
      default:
        return { error: `Unknown tool: ${name}` };
    }
  }

  /* ----------------------- persistence helpers ----------------------- */

  private saveCase(args: Record<string, unknown>): SavedCase {
    const indicators = Array.isArray(args.indicators) ? (args.indicators as string[]).map(String) : [];
    const actions = Array.isArray(args.recommended_actions)
      ? (args.recommended_actions as string[]).map(String)
      : [];
    const now = Date.now();

    const cursor = this.sql.exec<{ id: number }>(
      `INSERT INTO cases (title, summary, severity, verdict, indicators, recommended_actions, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id`,
      String(args.title ?? "Untitled case"),
      String(args.summary ?? ""),
      String(args.severity ?? "Low"),
      String(args.verdict ?? "Needs Review"),
      JSON.stringify(indicators),
      JSON.stringify(actions),
      now,
    );
    const id = cursor.one().id;

    return {
      id,
      title: String(args.title ?? "Untitled case"),
      summary: String(args.summary ?? ""),
      severity: String(args.severity ?? "Low"),
      verdict: String(args.verdict ?? "Needs Review"),
      indicators,
      recommended_actions: actions,
      created_at: now,
    };
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
    return rows.map((r) => ({ role: r.role as ChatMessage["role"], content: r.content }));
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

function parseArgs(raw: Record<string, unknown> | string): Record<string, unknown> {
  if (typeof raw === "string") {
    try {
      return JSON.parse(raw) as Record<string, unknown>;
    } catch {
      return {};
    }
  }
  return raw ?? {};
}

function safeParseArray(raw: string): string[] {
  try {
    const v = JSON.parse(raw);
    return Array.isArray(v) ? v.map(String) : [];
  } catch {
    return [];
  }
}
