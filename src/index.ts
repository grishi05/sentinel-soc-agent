/**
 * index.ts — Worker entry point.
 *
 * Thanks to `assets.run_worker_first: ["/api/*"]` in wrangler.jsonc, this Worker
 * is only invoked for /api/* routes; the chat UI in ./public is served directly
 * from the edge for everything else. Each request carries a sessionId that we map
 * to a single TriageAgent Durable Object instance (the session's private memory).
 */

import { TriageAgent, type Env } from "./agent";

// The Durable Object class must be exported from the Worker's main module.
export { TriageAgent };

const json = (data: unknown, status = 200): Response =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });

/** Resolve the per-session agent stub. Session id comes from the client. */
function agentFor(env: Env, sessionId: string) {
  const id = env.TRIAGE_AGENT.idFromName(sessionId);
  return env.TRIAGE_AGENT.get(id);
}

function sanitizeSession(raw: string | null): string {
  const s = (raw ?? "").trim();
  // Keep it to a sane, opaque token; fall back to a shared lobby if missing.
  return /^[A-Za-z0-9_-]{8,128}$/.test(s) ? s : "anonymous-session";
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    try {
      // POST /api/chat  { sessionId, message }
      if (url.pathname === "/api/chat" && request.method === "POST") {
        const body = (await request.json().catch(() => ({}))) as {
          sessionId?: string;
          message?: string;
        };
        const sessionId = sanitizeSession(body.sessionId ?? null);
        const message = String(body.message ?? "");
        const result = await agentFor(env, sessionId).chat(message);
        return json(result);
      }

      // GET /api/history?sessionId=...
      if (url.pathname === "/api/history" && request.method === "GET") {
        const sessionId = sanitizeSession(url.searchParams.get("sessionId"));
        const result = await agentFor(env, sessionId).history();
        return json(result);
      }

      // POST /api/reset  { sessionId }
      if (url.pathname === "/api/reset" && request.method === "POST") {
        const body = (await request.json().catch(() => ({}))) as { sessionId?: string };
        const sessionId = sanitizeSession(body.sessionId ?? null);
        const result = await agentFor(env, sessionId).reset();
        return json(result);
      }

      return json({ error: "Not found" }, 404);
    } catch (err) {
      console.error("Sentinel error:", err);
      return json({ error: "Internal error", detail: String(err) }, 500);
    }
  },
} satisfies ExportedHandler<Env>;
