# Prompt History

This project was built with AI‑assisted coding (Claude Code). The assignment requires submitting
prompt history, so this file logs the prompts and key decisions that drove the build, in order.

---

### 1. Initial assignment prompt
> We plan to fast‑track candidates who complete an assignment to build an AI‑powered application on
> Cloudflare. It should include: an LLM (recommend Llama 3.3 on Workers AI), workflow/coordination
> (Workflows / Workers / Durable Objects), user input via chat or voice (Pages or Realtime), and
> memory or state. AI‑assisted coding is encouraged, but you have to submit prompt history.
> Build an optional project and push it to my GitHub.

### 2. Scoping decisions (clarifying Q&A)
Three decisions were locked before coding:
- **Concept:** an AI **SOC (Security Operations Center) triage agent** — fits a cybersecurity
  portfolio and naturally exercises all four required components.
- **Scope:** build the full codebase, verify it locally (typecheck + tests + dry‑run bundle), push
  to GitHub, and include one‑command deploy docs. The final `wrangler deploy` is run by the account
  owner.
- **Prompt log:** maintain this file.

### 3. Grounding in the current Cloudflare API (before writing code)
> Before coding, pull the authoritative current docs/versions: the Workers AI function‑calling API
> shape, and the exact Llama 3.3 model ID + whether it supports tools/streaming.

Findings that shaped the code:
- Model id: `@cf/meta/llama-3.3-70b-instruct-fp8-fast` (supports function calling + streaming).
- Tool calling: pass `tools: [{ name, description, parameters }]`; read back
  `response.tool_calls[0].{name, arguments}`; return results as `{ role: "tool", content }` messages.

### 4. Architecture decision
> The bleeding‑edge agents‑starter template (AI SDK v6, `@cloudflare/ai-chat`, Vite 8) churns fast
> and is fragile to pin. For a portfolio piece the user deploys themselves, prefer **stable, first‑
> class Cloudflare primitives** that still satisfy every requirement.

Chosen design:
- **Worker** (`src/index.ts`) → routes `/api/*` to a per‑session **Durable Object**.
- **TriageAgent Durable Object** (`src/agent.ts`) → runs the LLM tool‑calling loop and holds memory
  in embedded **SQLite** (`messages` + `cases`).
- **Workers AI Llama 3.3** via the `env.AI` binding.
- **Static chat UI** (`public/index.html`) served from the edge — no frontend build step to break
  the user's deploy.

### 5. Implementation prompts
- "Write the analyst toolbox as pure, unit‑testable functions: `extract_indicators` (with a refang
  step for defanged IOCs), `assess_indicator` (offline heuristics with a marked hook for real threat
  intel), `score_alert`, `recommend_actions`. Add the tool JSON schemas for Workers AI."
- "Write the `TriageAgent` Durable Object: init SQLite tables in `blockConcurrencyWhile`, expose
  `chat` / `history` / `reset` RPC methods, and an agent loop capped at 8 tool steps that feeds tool
  results back to the model and persists a `save_case_note` as memory."
- "Write a system prompt that makes the model run the triage workflow with tools, stay defensive,
  and never claim live‑TI reputation from the offline heuristics."
- "Build a polished single‑file SOC‑console chat UI: chat pane + live verdict panel + case‑file
  list, example chips, session id in localStorage, history restore on load."

### 6. Test‑driven fixes (verification loop)
> Run typecheck, the unit tests, and a `wrangler deploy --dry-run`.

Issues caught and fixed during verification:
- **Durable Object branding:** `TriageAgent` must `extend DurableObject<Env>` from
  `cloudflare:workers` for RPC methods to appear on the stub and to satisfy the type brand.
- **Scoring thresholds:** unit tests showed a bare URL shortener and a raw‑IP URL were landing in
  "medium"; tuned the heuristic weights and risk bands so they correctly read as "high", and made a
  standalone file hash neutral ("info") since it can't be judged offline.

Final state: `tsc` clean, **12/12** unit tests passing, Worker bundles and both bindings
(`TRIAGE_AGENT` Durable Object + `AI`) resolve in the dry‑run.

> Note: live Llama 3.3 inference was not exercised locally — it requires the account owner's
> `wrangler login`. Everything up to the model call (routing, agent loop wiring, tools, SQLite
> memory, UI, bundling, bindings) was verified.
