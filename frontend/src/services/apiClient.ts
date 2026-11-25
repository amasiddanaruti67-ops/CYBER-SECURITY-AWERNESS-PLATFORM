import { apkProfiles, phishingScenarios, mockUrlAnalysis } from "../data/mockData";
import type { ApkAnalysisResponse, ApkProfile, PhishingScenario, SimulationEvent, UrlAnalysis } from "../types/cyber";

const API_BASE = "http://localhost:8000";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, init);
  if (!response.ok) {
    throw new Error(`API request failed (${response.status})`);
  }
  return response.json() as Promise<T>;
}

export async function getScenarios(): Promise<{ scenarios: PhishingScenario[]; apkProfiles: ApkProfile[]; source: "api" | "demo" }> {
  try {
    const data = await request<{ scenarios: PhishingScenario[]; apkProfiles: ApkProfile[] }>("/api/scenarios");
    return { ...data, source: "api" };
  } catch (error) {
    if (error instanceof TypeError) {
      return { scenarios: phishingScenarios, apkProfiles, source: "demo" };
    }
    throw error;
  }
}

export async function recordSimulationEvent(event: SimulationEvent): Promise<void> {
  try {
    await request("/api/events/simulation", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(event),
    });
  } catch (error) {
    if (!(error instanceof TypeError)) throw error;
  }
}

export async function analyzeUrl(url: string): Promise<{ analysis: UrlAnalysis; source: "api" | "demo" }> {
  try {
    const analysis = await request<UrlAnalysis>("/api/analyze/url", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    return { analysis, source: "api" };
  } catch (error) {
    if (!(error instanceof TypeError)) throw error;
    const normalized = normalizeUrl(url);
    if (!normalized) throw new Error("Enter a valid http or https URL.");
    const host = new URL(normalized).hostname;
    const urlObject = new URL(normalized);
    const punycode = host.includes("xn--");
    const redirectParameter = ["redirect", "redirect_uri", "next", "return", "continue", "url", "target"]
      .find((key) => urlObject.searchParams.has(key));
    const suspicious = /login|verify|secure|account|update|auth|refund/i.test(host) || punycode || Boolean(redirectParameter) || Boolean(urlObject.username);
    const reasons = suspicious
      ? [
        ...(punycode ? ["Punycode label detected; check for visually similar Unicode characters."] : []),
        ...(redirectParameter ? [`Redirect-like parameter detected (${redirectParameter}); destination was not followed.`] : []),
        ...(urlObject.username ? ["User-info appears before the hostname and may disguise the actual destination."] : []),
        ...(/login|verify|secure|account|update|auth|refund/i.test(host) ? ["Account or verification language in the host is a common impersonation signal."] : []),
        "Offline mode cannot verify domain age, reputation, or the live destination.",
      ]
      : ["No obvious host impersonation pattern detected by the local heuristics.", "Offline mode cannot verify domain age, reputation, or the live destination."];
    return {
      source: "demo",
      analysis: {
        ...mockUrlAnalysis,
        normalizedUrl: normalized,
        host,
        riskScore: suspicious ? 82 : 28,
        reasons,
        hops: [
          { label: "Submitted URL", detail: normalized, status: "safe" },
          { label: "Host heuristics", detail: suspicious ? "Potential impersonation pattern" : "No obvious local pattern", status: suspicious ? "danger" : "safe" },
          { label: "TLS syntax", detail: normalized.startsWith("https:") ? "HTTPS requested; certificate not checked" : "HTTP is not encrypted", status: normalized.startsWith("https:") ? "warning" : "danger" },
        ],
        tls: normalized.startsWith("https:") ? "HTTPS requested; certificate validity was not checked offline." : "HTTP URL; transport is not encrypted.",
      },
    };
  }
}

export async function analyzeApk(file: File): Promise<ApkAnalysisResponse | null> {
  const form = new FormData();
  form.append("file", file);
  try {
    return await request<ApkAnalysisResponse>("/api/analyze/apk", { method: "POST", body: form });
  } catch (error) {
    if (error instanceof TypeError) return null;
    throw error;
  }
}

export function normalizeUrl(input: string): string | null {
  const value = input.trim();
  if (!value) return null;
  try {
    const url = new URL(/^[a-z][a-z\d+.-]*:/i.test(value) ? value : `https://${value}`);
    return url.protocol === "http:" || url.protocol === "https:" ? url.href : null;
  } catch {
    return null;
  }
}
