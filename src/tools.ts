/**
 * tools.ts — the SOC analyst's toolbox.
 *
 * These are the deterministic building blocks the LLM orchestrates. Keeping the
 * heavy lifting in plain, pure functions (no network, no model) means:
 *   - the agent's reasoning is auditable and reproducible, and
 *   - every function here is unit-testable without Cloudflare or an API key
 *     (see test/tools.test.ts).
 *
 * The schemas in `toolDefinitions` are what we hand to Workers AI so Llama 3.3
 * can decide when to call each tool (Workers AI function calling).
 */

export type IndicatorType = "ip" | "domain" | "url" | "email" | "hash";

/* ------------------------------------------------------------------ *
 * 1. extract_indicators — pull IOCs out of raw alert / log / email text
 * ------------------------------------------------------------------ */

export interface ExtractedIndicators {
  ipv4: string[];
  domains: string[];
  urls: string[];
  emails: string[];
  hashes: string[];
  cves: string[];
  count: number;
}

/**
 * Many real-world alerts arrive "defanged" so they aren't accidentally clicked,
 * e.g. `hxxps://bad[.]example[.]com`. We re-fang a copy before extracting.
 */
export function refang(text: string): string {
  return text
    .replace(/h\s*x\s*x\s*p/gi, "http")
    .replace(/\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}/g, ".")
    .replace(/\[\s*dot\s*\]/gi, ".")
    .replace(/\[\s*:\s*\]/g, ":")
    .replace(/\[\s*@\s*\]|\(\s*@\s*\)/g, "@")
    .replace(/\[\s*at\s*\]/gi, "@");
}

function uniqueLower(values: string[]): string[] {
  return [...new Set(values.map((v) => v.toLowerCase()))];
}

function isValidIpv4(ip: string): boolean {
  const parts = ip.split(".");
  if (parts.length !== 4) return false;
  return parts.every((p) => {
    const n = Number(p);
    return p.length > 0 && p.length <= 3 && n >= 0 && n <= 255;
  });
}

export function extractIndicators(text: string): ExtractedIndicators {
  const clean = refang(text ?? "");

  const urls = uniqueLower(clean.match(/\bhttps?:\/\/[^\s"'<>)\]]+/gi) ?? []);
  const emails = uniqueLower(
    clean.match(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g) ?? [],
  );
  const ipv4 = [
    ...new Set((clean.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) ?? []).filter(isValidIpv4)),
  ];

  // sha256 (64) before sha1 (40) before md5 (32); \b anchoring keeps them distinct.
  const hashes = uniqueLower([
    ...(clean.match(/\b[a-fA-F0-9]{64}\b/g) ?? []),
    ...(clean.match(/\b[a-fA-F0-9]{40}\b/g) ?? []),
    ...(clean.match(/\b[a-fA-F0-9]{32}\b/g) ?? []),
  ]);

  const cves = [...new Set((clean.match(/\bCVE-\d{4}-\d{4,7}\b/gi) ?? []).map((c) => c.toUpperCase()))];

  // Domains: capture everything that looks like a hostname, then drop the ones
  // we already accounted for inside emails or URLs so we don't double-count.
  const emailDomains = emails.map((e) => e.split("@")[1]);
  const urlHosts = urls
    .map((u) => {
      try {
        return new URL(u).hostname.toLowerCase();
      } catch {
        return "";
      }
    })
    .filter(Boolean);

  const rawDomains = uniqueLower(
    clean.match(/\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g) ?? [],
  ).filter((d) => !isValidIpv4(d));

  const accountedFor = new Set([...emailDomains, ...urlHosts]);
  const domains = rawDomains.filter((d) => !accountedFor.has(d));

  const count =
    ipv4.length + domains.length + urls.length + emails.length + hashes.length + cves.length;

  return { ipv4, domains, urls, emails, hashes, cves, count };
}

/* ------------------------------------------------------------------ *
 * 2. assess_indicator — heuristic risk score for a single IOC
 *
 *    NOTE: this is intentionally offline. It applies well-known SOC
 *    heuristics rather than calling a live threat-intel feed, so the
 *    demo is self-contained and reproducible. assessIndicator() is the
 *    one clean place to drop in a real VirusTotal / AbuseIPDB lookup
 *    (see the `// REAL-TI HOOK` marker).
 * ------------------------------------------------------------------ */

export type RiskBand = "info" | "low" | "medium" | "high";

export interface IndicatorAssessment {
  indicator: string;
  type: IndicatorType;
  score: number; // 0-100
  risk: RiskBand;
  reasons: string[];
}

const URL_SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "is.gd", "goo.gl", "ow.ly", "buff.ly",
  "rebrand.ly", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc",
]);

// TLDs disproportionately abused for phishing / malware delivery.
const SUSPICIOUS_TLDS = new Set([
  "zip", "mov", "xyz", "top", "tk", "gq", "ml", "cf", "ga", "country",
  "click", "work", "link", "live", "rest", "fit", "review", "kim", "loan",
]);

const BRAND_KEYWORDS = [
  "paypal", "microsoft", "office365", "outlook", "apple", "icloud", "google",
  "amazon", "netflix", "facebook", "instagram", "linkedin", "bank", "wellsfargo",
  "chase", "coinbase", "binance", "login", "signin", "secure", "verify",
  "account", "update", "confirm", "support", "helpdesk", "reset", "mfa",
];

function bandFromScore(score: number): RiskBand {
  if (score >= 65) return "high";
  if (score >= 35) return "medium";
  if (score >= 15) return "low";
  return "info";
}

function isPrivateOrReserved(ip: string): boolean {
  const [a, b] = ip.split(".").map(Number);
  if (a === 10 || a === 127 || a === 0) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 169 && b === 254) return true;
  if (a >= 224) return true; // multicast / reserved
  return false;
}

function tldOf(host: string): string {
  const parts = host.split(".");
  return parts[parts.length - 1] ?? "";
}

export function assessIndicator(indicator: string, type: IndicatorType): IndicatorAssessment {
  const value = (indicator ?? "").trim();
  const reasons: string[] = [];
  let score = 0;

  // REAL-TI HOOK: a production build would `await` a reputation lookup here
  // (VirusTotal / AbuseIPDB / URLhaus) and fold the verdict into `score`.

  if (type === "ip") {
    if (isPrivateOrReserved(value)) {
      reasons.push("RFC1918 / reserved address — internal or non-routable");
      score = 5;
    } else {
      reasons.push("Public, routable IPv4 address — pivot point worth checking against TI");
      score = 30;
    }
  } else if (type === "hash") {
    reasons.push("File hash cannot be judged offline — submit to a sandbox / VT for a verdict");
    score = 10;
  } else {
    // url / domain / email all key off the hostname.
    let host = value.toLowerCase();
    let hasUserInfo = false;
    let rawIpHost = false;

    if (type === "url") {
      try {
        const u = new URL(value);
        host = u.hostname.toLowerCase();
        hasUserInfo = u.username.length > 0 || value.includes("@");
        rawIpHost = isValidIpv4Host(host);
      } catch {
        reasons.push("Malformed URL");
        host = value.toLowerCase();
      }
    } else if (type === "email") {
      host = value.split("@")[1]?.toLowerCase() ?? value;
    }

    if (URL_SHORTENERS.has(host)) {
      reasons.push("URL shortener — masks the true destination");
      score += 65;
    }
    if (rawIpHost) {
      reasons.push("Uses a raw IP address instead of a hostname");
      score += 75;
    }
    if (hasUserInfo) {
      reasons.push("Embedded credentials / userinfo in URL — classic obfuscation");
      score += 45;
    }
    if (host.includes("xn--")) {
      reasons.push("Punycode (xn--) host — possible IDN homograph / lookalike");
      score += 50;
    }
    const tld = tldOf(host);
    if (SUSPICIOUS_TLDS.has(tld)) {
      reasons.push(`Low-reputation TLD ".${tld}" — frequently abused`);
      score += 35;
    }
    const labels = host.split(".");
    if (labels.length >= 5) {
      reasons.push("Unusually deep subdomain chain");
      score += 20;
    }
    if ((host.match(/-/g) ?? []).length >= 3) {
      reasons.push("Many hyphens — common in generated phishing domains");
      score += 20;
    }
    if (/\d/.test(host.replace(/\./g, "")) && /[a-z]{6,}\d{3,}/.test(host)) {
      reasons.push("Random-looking alphanumeric host");
      score += 15;
    }
    const brandHit = BRAND_KEYWORDS.find((kw) => host.includes(kw));
    if (brandHit) {
      reasons.push(`Contains trust/brand keyword "${brandHit}" in the hostname — impersonation risk`);
      score += 40;
    }
    if (score === 0) {
      reasons.push("No strong heuristic signals — treat as unknown, corroborate with TI");
      score = 25;
    }
  }

  score = Math.max(0, Math.min(100, score));
  return { indicator: value, type, score, risk: bandFromScore(score), reasons };
}

function isValidIpv4Host(host: string): boolean {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host) && isValidIpv4(host);
}

/* ------------------------------------------------------------------ *
 * 3. score_alert — combine signals into an overall severity
 * ------------------------------------------------------------------ */

export type Severity = "Low" | "Medium" | "High" | "Critical";

export interface AlertScore {
  severity: Severity;
  score: number; // 0-100
  rationale: string;
}

export interface ScoreAlertInput {
  highRiskIndicators?: number;
  mediumRiskIndicators?: number;
  affectsCriticalAsset?: boolean;
  confirmedMalicious?: boolean;
  userInteraction?: boolean; // e.g. a user already clicked / entered creds
  signals?: string[];
}

export function scoreAlert(input: ScoreAlertInput): AlertScore {
  const high = Math.max(0, input.highRiskIndicators ?? 0);
  const medium = Math.max(0, input.mediumRiskIndicators ?? 0);

  let score = Math.min(60, high * 25 + medium * 10);
  const parts: string[] = [];
  if (high) parts.push(`${high} high-risk indicator(s)`);
  if (medium) parts.push(`${medium} medium-risk indicator(s)`);

  if (input.confirmedMalicious) {
    score += 30;
    parts.push("confirmed-malicious signal");
  }
  if (input.affectsCriticalAsset) {
    score += 20;
    parts.push("touches a critical asset");
  }
  if (input.userInteraction) {
    score += 20;
    parts.push("user interaction already occurred");
  }
  for (const _ of input.signals ?? []) score += 3;

  score = Math.max(0, Math.min(100, score));

  let severity: Severity = "Low";
  if (score >= 80) severity = "Critical";
  else if (score >= 55) severity = "High";
  else if (score >= 30) severity = "Medium";

  const rationale =
    parts.length > 0
      ? `Severity ${severity} (score ${score}) driven by: ${parts.join(", ")}.`
      : `Severity ${severity} (score ${score}) — limited corroborating signals.`;

  return { severity, score, rationale };
}

/* ------------------------------------------------------------------ *
 * 4. recommend_actions — map a verdict to a SOC playbook
 * ------------------------------------------------------------------ */

export type Category = "phishing" | "malware" | "network" | "recon" | "credential" | "other";

export interface ActionPlan {
  immediate: string[];
  investigation: string[];
  remediation: string[];
}

export function recommendActions(severity: Severity, category: Category): ActionPlan {
  const plan: ActionPlan = { immediate: [], investigation: [], remediation: [] };

  // Severity drives urgency / escalation.
  if (severity === "Critical" || severity === "High") {
    plan.immediate.push("Escalate to Tier-2 / IR on-call now");
    plan.immediate.push("Open an incident ticket and start a timeline");
  } else {
    plan.immediate.push("Log the triage and continue monitoring");
  }

  switch (category) {
    case "phishing":
      plan.immediate.push("Quarantine the message and pull identical copies from other mailboxes");
      plan.investigation.push("Identify all recipients and check who clicked or replied");
      plan.investigation.push("Detonate the URL/attachment in a sandbox");
      plan.remediation.push("Block sender domain, URLs, and any payload hashes at mail + proxy");
      plan.remediation.push("Force password reset for any user who entered credentials");
      break;
    case "malware":
      plan.immediate.push("Isolate the affected host from the network");
      plan.investigation.push("Collect the sample hash and run it through AV/sandbox");
      plan.investigation.push("Review EDR process tree and persistence mechanisms");
      plan.remediation.push("Block the payload hash and C2 indicators org-wide");
      plan.remediation.push("Reimage the host if integrity cannot be assured");
      break;
    case "network":
      plan.investigation.push("Pull firewall/proxy logs for the source and destination IPs");
      plan.investigation.push("Check for beaconing patterns and data-transfer volume");
      plan.remediation.push("Block the malicious IP/port at the perimeter");
      break;
    case "recon":
      plan.investigation.push("Correlate scanning source against threat intel and prior events");
      plan.remediation.push("Rate-limit or block the scanning source; confirm exposed services are patched");
      break;
    case "credential":
      plan.immediate.push("Disable or force-reset the affected account");
      plan.investigation.push("Review auth logs for successful logins from anomalous geos/devices");
      plan.remediation.push("Enforce MFA and revoke active sessions/tokens");
      break;
    default:
      plan.investigation.push("Gather additional context and corroborate indicators with TI");
  }

  plan.remediation.push("Record indicators in the case file for future correlation");
  return plan;
}

/* ------------------------------------------------------------------ *
 * Tool schemas handed to Workers AI (Llama 3.3 function calling)
 * ------------------------------------------------------------------ */

export const toolDefinitions = [
  {
    name: "extract_indicators",
    description:
      "Extract indicators of compromise (IPv4, domains, URLs, emails, file hashes, CVE IDs) from raw alert, log, or email text. Handles defanged input like hxxp and [.]. Always call this first on any submitted artifact.",
    parameters: {
      type: "object",
      properties: {
        text: { type: "string", description: "The raw text to scan for indicators." },
      },
      required: ["text"],
    },
  },
  {
    name: "assess_indicator",
    description:
      "Heuristically risk-score a single indicator (offline — no live threat-intel feed). Call once per notable indicator found.",
    parameters: {
      type: "object",
      properties: {
        indicator: { type: "string", description: "The indicator value, e.g. a URL or IP." },
        type: {
          type: "string",
          enum: ["ip", "domain", "url", "email", "hash"],
          description: "The kind of indicator.",
        },
      },
      required: ["indicator", "type"],
    },
  },
  {
    name: "score_alert",
    description:
      "Combine signals into an overall severity (Low/Medium/High/Critical). Call after assessing indicators.",
    parameters: {
      type: "object",
      properties: {
        highRiskIndicators: { type: "number", description: "Count of high-risk indicators." },
        mediumRiskIndicators: { type: "number", description: "Count of medium-risk indicators." },
        affectsCriticalAsset: { type: "boolean", description: "Does this touch a critical asset?" },
        confirmedMalicious: { type: "boolean", description: "Is anything confirmed malicious?" },
        userInteraction: { type: "boolean", description: "Did a user already click / enter creds?" },
        signals: { type: "array", items: { type: "string" }, description: "Other notable signals." },
      },
      required: ["highRiskIndicators", "mediumRiskIndicators"],
    },
  },
  {
    name: "recommend_actions",
    description:
      "Return a SOC response playbook (immediate / investigation / remediation steps) for the given severity and category.",
    parameters: {
      type: "object",
      properties: {
        severity: { type: "string", enum: ["Low", "Medium", "High", "Critical"] },
        category: {
          type: "string",
          enum: ["phishing", "malware", "network", "recon", "credential", "other"],
        },
      },
      required: ["severity", "category"],
    },
  },
  {
    name: "save_case_note",
    description:
      "Persist the finalized triage to the session case file (memory). Call this once at the end of a triage so the finding is recorded and can be recalled later.",
    parameters: {
      type: "object",
      properties: {
        title: { type: "string", description: "Short title for the case." },
        summary: { type: "string", description: "1-3 sentence analyst summary." },
        severity: { type: "string", enum: ["Low", "Medium", "High", "Critical"] },
        verdict: {
          type: "string",
          enum: ["Benign", "Suspicious", "Malicious", "Needs Review"],
        },
        indicators: { type: "array", items: { type: "string" }, description: "Key indicators." },
        recommended_actions: {
          type: "array",
          items: { type: "string" },
          description: "Top recommended actions.",
        },
      },
      required: ["title", "summary", "severity", "verdict"],
    },
  },
] as const;
