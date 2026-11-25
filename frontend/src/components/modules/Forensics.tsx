import { useState } from "react";
import { AlertTriangle, ArrowRightLeft, CheckCircle2, Globe2, LoaderCircle, Search, ShieldCheck } from "lucide-react";
import TrustChain from "./TrustChain";
import { analyzeUrl } from "../../services/apiClient";
import type { UrlAnalysis } from "../../types/cyber";

type Mode = "url" | "headers";

const sampleHeaders = `From: Security Desk <notices@secure-account-check.com>
Reply-To: help@different-support.co
Return-Path: <bounce@mailer-unknown.net>
Authentication-Results: mx.example; spf=fail; dkim=none; dmarc=fail
Received: from relay.mailer-unknown.net (203.0.113.42)
Subject: Verify your account immediately`;

function inspectHeaders(raw: string): { analysis: UrlAnalysis; signals: string[] } {
  const get = (name: string) => raw.match(new RegExp(`^${name}:\\s*(.+)$`, "im"))?.[1]?.trim() ?? "Not present";
  const from = get("From");
  const replyTo = get("Reply-To");
  const auth = get("Authentication-Results");
  const mismatch = replyTo !== "Not present" && from.toLowerCase().split("@").pop() !== replyTo.toLowerCase().split("@").pop();
  const failedAuth = /\b(spf|dkim|dmarc)=(fail|none|softfail)\b/i.test(auth);
  const signals = [
    mismatch ? `Reply-To domain differs from From: ${replyTo}` : "From and Reply-To domains appear aligned or Reply-To is absent.",
    failedAuth ? `Authentication results contain a failure or missing check: ${auth}` : `Authentication results: ${auth}`,
    get("Return-Path") !== "Not present" ? `Return-Path: ${get("Return-Path")}` : "Return-Path is not present.",
  ];
  return {
    signals,
    analysis: {
      normalizedUrl: from,
      host: from.match(/@([^>\s]+)/)?.[1] ?? "Unknown sender",
      riskScore: Math.min(98, (mismatch ? 42 : 8) + (failedAuth ? 42 : 8)),
      reasons: signals,
      hops: [
        { label: "From identity", detail: from, status: mismatch ? "warning" : "safe" },
        { label: "Reply-To alignment", detail: replyTo, status: mismatch ? "danger" : "safe" },
        { label: "SPF / DKIM / DMARC", detail: auth, status: failedAuth ? "danger" : "safe" },
        { label: "Return path", detail: get("Return-Path"), status: "warning" },
      ],
      tls: "Email headers do not prove the sender's live transport certificate.",
      domainAge: "Not available from the provided headers; no WHOIS lookup is performed.",
      authentication: auth,
    },
  };
}

export default function Forensics() {
  const [mode, setMode] = useState<Mode>("url");
  const [input, setInput] = useState("");
  const [analysis, setAnalysis] = useState<UrlAnalysis | null>(null);
  const [source, setSource] = useState<"api" | "demo" | "local" | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const runAnalysis = async () => {
    setError("");
    if (!input.trim()) { setError(mode === "url" ? "Enter a URL to inspect." : "Paste raw headers to inspect."); return; }
    if (mode === "headers") {
      const result = inspectHeaders(input);
      setAnalysis(result.analysis);
      setSource("local");
      return;
    }
    setBusy(true);
    try {
      const result = await analyzeUrl(input);
      setAnalysis(result.analysis);
      setSource(result.source);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "URL could not be analyzed.");
    } finally {
      setBusy(false);
    }
  };

  const loadSample = () => {
    setMode("headers");
    setInput(sampleHeaders);
    const result = inspectHeaders(sampleHeaders);
    setAnalysis(result.analysis);
    setSource("local");
    setError("");
  };

  return (
    <div className="fade-in space-y-5">
      <header><p className="eyebrow">INVESTIGATION / TRUST & AUTHENTICATION</p><h1 className="mt-2 text-2xl font-bold text-white sm:text-3xl">URL & email forensics</h1><p className="mt-1 text-sm text-slate-400">Explainable, static indicators. No link is opened and no external reputation lookup is made.</p></header>
      <div className="grid gap-4 xl:grid-cols-[.9fr_1.1fr]">
        <section className="panel rounded-xl p-5">
          <div className="flex items-center gap-2 text-xs text-slate-300"><Globe2 size={15} className="text-cyan" /> EVIDENCE INPUT</div>
          <div className="mt-4 flex rounded-lg border border-white/5 bg-ink p-1">
            <button onClick={() => { setMode("url"); setAnalysis(null); }} className={`flex-1 rounded-md py-2 text-[11px] font-semibold ${mode === "url" ? "bg-cyan/10 text-cyan" : "text-slate-500 hover:text-slate-300"}`}>Suspicious URL</button>
            <button onClick={() => { setMode("headers"); setAnalysis(null); }} className={`flex-1 rounded-md py-2 text-[11px] font-semibold ${mode === "headers" ? "bg-cyan/10 text-cyan" : "text-slate-500 hover:text-slate-300"}`}>Raw email headers</button>
          </div>
          {mode === "url" ? <input value={input} onChange={(event) => setInput(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") void runAnalysis(); }} placeholder="https://example.com/account/verify" className="mt-4 w-full rounded-lg border border-white/10 bg-ink px-3 py-3 font-mono text-xs text-white outline-none placeholder:text-slate-700 focus:border-cyan/40" /> : <textarea value={input} onChange={(event) => setInput(event.target.value)} rows={8} placeholder={"From: sender@example.com\nReply-To: support@example.com\nAuthentication-Results: spf=pass; dkim=pass; dmarc=pass"} className="mt-4 w-full resize-y rounded-lg border border-white/10 bg-ink px-3 py-3 font-mono text-[10px] leading-relaxed text-white outline-none placeholder:text-slate-700 focus:border-cyan/40" />}
          <div className="mt-3 flex flex-wrap gap-2"><button onClick={() => void runAnalysis()} disabled={busy} className="inline-flex items-center gap-2 rounded-lg bg-cyan px-4 py-2.5 text-xs font-bold text-ink hover:bg-cyan/80 disabled:opacity-50">{busy ? <LoaderCircle size={14} className="animate-spin" /> : <Search size={14} />} Analyze evidence</button><button onClick={loadSample} className="rounded-lg border border-white/10 px-3 py-2.5 text-xs text-slate-400 hover:border-white/20 hover:text-white">Load header sample</button></div>
          {error && <p role="alert" className="mt-3 text-xs text-danger">{error}</p>}
          <div className="mt-5 grid gap-3 sm:grid-cols-2"><div className="rounded-lg border border-white/5 bg-white/[.02] p-3"><div className="flex items-center gap-2 text-[10px] font-semibold text-amber"><AlertTriangle size={13} /> PUNYCODE / HOMOGRAPHS</div><p className="mt-2 text-[10px] leading-relaxed text-slate-500">An xn-- label or unusual script may imitate a familiar domain. This is a warning signal, not proof.</p></div><div className="rounded-lg border border-white/5 bg-white/[.02] p-3"><div className="flex items-center gap-2 text-[10px] font-semibold text-cyan"><ShieldCheck size={13} /> STATIC ONLY</div><p className="mt-2 text-[10px] leading-relaxed text-slate-500">Offline checks inspect syntax and pasted headers only; they cannot validate live DNS, TLS, WHOIS, or redirects.</p></div></div>
        </section>
        <section className="panel rounded-xl p-5">
          <div className="flex items-center justify-between"><div><p className="eyebrow">EXPLAINABLE TRUST HOP CHAIN</p><p className="mt-1 text-xs text-slate-500">Evidence path & visible signals</p></div>{source && <span className="rounded border border-cyan/15 bg-cyan/[.04] px-2 py-1 font-mono text-[9px] text-cyan">{source === "local" ? "LOCAL HEADER CHECK" : source === "api" ? "API ANALYSIS" : "OFFLINE DEMO"}</span>}</div>
          {analysis ? <>
            <div className="mt-5 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-white/5 bg-ink/70 p-3"><div className="min-w-0"><p className="eyebrow">SUBJECT</p><p className="mt-1 break-all font-mono text-[11px] text-slate-300">{analysis.host || analysis.normalizedUrl}</p></div><div className={`font-mono text-xl font-bold ${analysis.riskScore >= 70 ? "text-danger" : analysis.riskScore >= 40 ? "text-amber" : "text-cyan"}`}>{analysis.riskScore}<span className="text-[10px] text-slate-500">/100</span></div></div>
            <div className="mt-5"><TrustChain analysis={analysis} /></div>
            <div className="grid gap-2 border-t border-white/5 pt-4 sm:grid-cols-3">{[["DOMAIN AGE / WHOIS", analysis.domainAge], ["TLS / SSL", analysis.tls], ["SPF / DKIM / DMARC", analysis.authentication]].map(([label, value]) => <div key={label} className="rounded-lg border border-white/5 p-3"><p className="eyebrow text-[8px]">{label}</p><p className="mt-2 text-[10px] leading-relaxed text-slate-400">{value}</p></div>)}</div>
            <div className="mt-4 space-y-2">{analysis.reasons.map((reason) => <p key={reason} className="flex gap-2 text-[10px] leading-relaxed text-slate-400"><ArrowRightLeft size={12} className="mt-0.5 shrink-0 text-amber" />{reason}</p>)}</div>
          </> : <div className="grid min-h-[420px] place-items-center text-center"><div><div className="mx-auto grid h-12 w-12 place-items-center rounded-full border border-white/10 text-slate-600"><CheckCircle2 size={20} /></div><p className="mt-3 text-xs text-slate-500">Submit a URL or paste email headers to see the trust chain.</p></div></div>}
        </section>
      </div>
    </div>
  );
}
