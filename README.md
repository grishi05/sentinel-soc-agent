# 🛡️ Sentinel — AI SOC Triage Agent on Cloudflare

Sentinel is an AI-powered **Security Operations Center (SOC) Tier‑1 triage analyst**. Paste a
suspicious email, an alert, a log line, or a single indicator, and Sentinel will:

1. **Extract** indicators of compromise (IPs, domains, URLs, emails, file hashes, CVEs) — even from
   *defanged* text like `hxxps://bad[.]example[.]com`.
2. **Assess** each indicator with SOC heuristics (URL shorteners, raw‑IP hosts, punycode/IDN
   lookalikes, low‑reputation TLDs, brand‑impersonation keywords, RFC1918 vs. public IPs…).
3. **Score** an overall severity (Low / Medium / High / Critical).
4. **Recommend** a concrete response playbook (immediate / investigation / remediation).
5. **Remember** the finding in a per‑session **case file** so analyses accumulate over time.

The LLM (Llama 3.3) drives the workflow by *calling these tools itself* — this is an agent, not a
single prompt.

> Built as the Cloudflare **AI‑powered application** fast‑track assignment. It is entirely
> **defensive**: it helps a human analyst understand and respond to threats. It does not aid offense.

---

## ✅ How it maps to the four required components

| Required component | How Sentinel implements it |
| --- | --- |
| **LLM** | **Llama 3.3 70B** on **Workers AI** (`@cf/meta/llama-3.3-70b-instruct-fp8-fast`) via the `env.AI` binding, using native **function calling**. |
| **Workflow / coordination** | A **Worker** routes requests to a **Durable Object** agent that runs a multi‑step **tool‑calling loop** (LLM → tool → LLM → … → save case). See [`src/agent.ts`](src/agent.ts). |
| **User input (chat)** | A single‑page **chat console** served from the edge via **Workers static assets** (the Pages‑equivalent). See [`public/index.html`](public/index.html). |
| **Memory / state** | Each session is one **Durable Object** with embedded **SQLite**: a `messages` table (conversation) and a `cases` table (saved triage findings), persisted across requests and restarts. |

---

## 🏗️ Architecture

```
Browser (chat UI, public/index.html)
        │  POST /api/chat { sessionId, message }
        ▼
Worker  (src/index.ts)                    ← only runs for /api/*; static assets served directly
        │  idFromName(sessionId)
        ▼
TriageAgent  (Durable Object, src/agent.ts)
        ├─ SQLite memory:  messages + cases
        └─ Agent loop:
              env.AI.run("@cf/meta/llama-3.3-70b-instruct-fp8-fast", { messages, tools })
                   │   tool_calls?
                   ├─ extract_indicators  ─┐
                   ├─ assess_indicator     │  pure, deterministic, unit-tested
                   ├─ score_alert          │  (src/tools.ts)
                   ├─ recommend_actions    │
                   └─ save_case_note  ─────┘  → writes to SQLite (memory)
```

Why **Durable Objects** instead of a stateless Worker? Each chat session needs private,
strongly‑consistent memory. `idFromName(sessionId)` deterministically routes a session to its own
agent instance, and the DO's embedded SQLite is the agent's long‑term memory — no external database
required.

### Project layout

| File | Purpose |
| --- | --- |
| [`src/index.ts`](src/index.ts) | Worker entry: routes `/api/chat`, `/api/history`, `/api/reset` to the per‑session agent. |
| [`src/agent.ts`](src/agent.ts) | `TriageAgent` Durable Object: the agent loop + SQLite memory. |
| [`src/tools.ts`](src/tools.ts) | The analyst toolbox (pure functions) + the tool schemas given to the LLM. |
| [`src/prompts.ts`](src/prompts.ts) | The Sentinel system prompt. |
| [`public/index.html`](public/index.html) | The SOC console chat UI (no build step). |
| [`test/tools.test.ts`](test/tools.test.ts) | Unit tests for the deterministic tool logic. |
| [`wrangler.jsonc`](wrangler.jsonc) | Bindings: AI, Durable Object, SQLite migration, static assets. |

---

## 🚀 Run & deploy

### Prerequisites
- Node 18+ and a **Cloudflare account** (the free plan includes a Workers AI allowance).
- [Wrangler](https://developers.cloudflare.com/workers/wrangler/) (installed locally as a dev dep).

### 1. Install
```bash
npm install
```

### 2. Verify locally (no account needed)
```bash
npm run typecheck   # TypeScript
npm test            # unit tests for the tool logic
npm run build       # wrangler dry-run bundle (validates bindings & config)
```

### 3. Develop
```bash
npm run dev
```
`wrangler dev` serves the UI and Worker locally. Workers AI inference runs against Cloudflare's
remote models, so the first model call will prompt you to log in (`wrangler login`).

### 4. Deploy to the edge
```bash
npm run deploy      # = wrangler deploy
```
Wrangler prints your live URL (e.g. `https://sentinel-soc-agent.<your-subdomain>.workers.dev`).
On first deploy it provisions the Durable Object + SQLite migration automatically. No secrets to
configure — Workers AI is accessed entirely through the `AI` binding.

---

## 🧪 Try it

Use the example chips in the UI, or paste:

```
Subject: Urgent: your account is locked
From: security@paypa1-support[.]com
Reply within 24h or lose access. Verify here: hxxps://secure-paypal-login[.]tk/verify?id=8842
```

Sentinel will refang the text, flag the lookalike domain + low‑reputation `.tk` TLD + brand keyword,
score it **High**, recommend quarantine + recipient sweep + credential reset, and save the case.

---

## 🔌 Extending to live threat intel

`assessIndicator()` in [`src/tools.ts`](src/tools.ts) is intentionally **offline and deterministic**
so the demo is self‑contained and reproducible. There is a single, clearly‑marked `// REAL-TI HOOK`
where a production build would `await` a reputation lookup (VirusTotal / AbuseIPDB / URLhaus) and fold
the verdict into the score — a clean place to add an API key via a Wrangler secret.

---

## 🧰 Tech & design notes

- **Stable primitives by choice.** This is built on first‑class, long‑stable Cloudflare APIs
  (Workers AI binding, Durable Objects + SQLite, Workers static assets) rather than a fast‑moving
  starter template, so it installs and deploys reliably. The same design maps cleanly onto the
  [Cloudflare Agents SDK](https://developers.cloudflare.com/agents/) (`AIChatAgent`), which wraps
  exactly these primitives.
- **No runtime dependencies.** Everything is reached through bindings; the only deps are dev tools
  (wrangler, typescript, vitest).
- **Auditable reasoning.** All scoring lives in pure functions with unit tests — the agent's
  "judgement" is inspectable, not a black box.

## License

MIT © grishi05
