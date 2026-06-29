import { describe, it, expect } from "vitest";
import {
  refang,
  extractIndicators,
  assessIndicator,
  scoreAlert,
  recommendActions,
} from "../src/tools";

describe("refang", () => {
  it("re-fangs defanged urls and domains", () => {
    expect(refang("hxxps://bad[.]example[.]com")).toBe("https://bad.example.com");
    expect(refang("user[at]evil[dot]com")).toBe("user@evil.com");
  });
});

describe("extractIndicators", () => {
  it("pulls IOCs out of a defanged phishing snippet", () => {
    const text = `From: security@paypa1-support[.]com
      Please verify at hxxps://paypa1-support[.]com/login
      Callback IP 203.0.113.45 and internal host 10.0.0.5
      Payload sha256: ` + "a".repeat(64) + `
      Related: CVE-2024-3094`;
    const ioc = extractIndicators(text);

    expect(ioc.urls).toContain("https://paypa1-support.com/login");
    expect(ioc.emails).toContain("security@paypa1-support.com");
    expect(ioc.ipv4).toEqual(expect.arrayContaining(["203.0.113.45", "10.0.0.5"]));
    expect(ioc.hashes).toContain("a".repeat(64));
    expect(ioc.cves).toContain("CVE-2024-3094");
    expect(ioc.count).toBeGreaterThan(0);
  });

  it("rejects invalid IPv4 octets", () => {
    expect(extractIndicators("999.1.1.1 is not valid").ipv4).toEqual([]);
  });

  it("does not double-count domains already inside emails/urls", () => {
    const ioc = extractIndicators("mail to a@known.com and visit https://known.com/x");
    expect(ioc.domains).not.toContain("known.com");
  });
});

describe("assessIndicator", () => {
  it("treats RFC1918 addresses as low risk", () => {
    const a = assessIndicator("10.0.0.5", "ip");
    expect(a.risk).toBe("info");
    expect(a.score).toBeLessThan(15);
  });

  it("flags public IPs as worth checking", () => {
    expect(assessIndicator("203.0.113.45", "ip").score).toBeGreaterThan(15);
  });

  it("scores URL shorteners and raw-IP URLs as high risk", () => {
    expect(assessIndicator("https://bit.ly/xyz", "url").risk).toBe("high");
    expect(assessIndicator("http://203.0.113.9/login", "url").score).toBeGreaterThanOrEqual(70);
  });

  it("flags brand-impersonation keywords in hostnames", () => {
    const a = assessIndicator("https://secure-paypal-login.tk/verify", "url");
    expect(a.risk).toBe("high");
    expect(a.reasons.join(" ")).toMatch(/brand|impersonation|TLD/i);
  });

  it("cannot judge a hash offline", () => {
    expect(assessIndicator("a".repeat(64), "hash").risk).toBe("info");
  });
});

describe("scoreAlert", () => {
  it("escalates with high-risk indicators and aggravating factors", () => {
    const low = scoreAlert({ highRiskIndicators: 0, mediumRiskIndicators: 1 });
    const crit = scoreAlert({
      highRiskIndicators: 2,
      mediumRiskIndicators: 1,
      confirmedMalicious: true,
      affectsCriticalAsset: true,
    });
    expect(low.severity).toBe("Low");
    expect(crit.severity).toBe("Critical");
    expect(crit.score).toBeGreaterThan(low.score);
  });
});

describe("recommendActions", () => {
  it("returns a phishing playbook with escalation for high severity", () => {
    const plan = recommendActions("High", "phishing");
    expect(plan.immediate.join(" ")).toMatch(/escalate/i);
    expect(plan.remediation.join(" ")).toMatch(/block/i);
  });

  it("isolates the host for malware", () => {
    expect(recommendActions("Critical", "malware").immediate.join(" ")).toMatch(/isolate/i);
  });
});
