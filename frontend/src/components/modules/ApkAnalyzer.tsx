import { useRef, useState } from "react";
import { AlertOctagon, CheckCircle2, FileArchive, Fingerprint, LoaderCircle, Shield, UploadCloud } from "lucide-react";
import { apkProfiles } from "../../data/mockData";
import { analyzeApk } from "../../services/apiClient";
import type { ApkAnalysisResponse, ApkProfile, PermissionFinding, RiskLevel } from "../../types/cyber";

const maxBytes = 50 * 1024 * 1024;
const explanations: Record<string, { level: RiskLevel; explanation: string }> = {
  RECEIVE_SMS: { level: "critical", explanation: "Can receive verification texts. Combined with other access, this may expose one-time codes." },
  READ_SMS: { level: "high", explanation: "Can read stored text messages, including financial alerts and verification codes." },
  BIND_ACCESSIBILITY_SERVICE: { level: "critical", explanation: "Accessibility access can observe or control screen interactions; rarely justified for a scanner." },
  SYSTEM_ALERT_WINDOW: { level: "high", explanation: "Can draw over other apps and imitate a trusted sign-in or payment screen." },
  READ_CONTACTS: { level: "high", explanation: "Can access your address book; consider whether the app's purpose requires it." },
  INTERNET: { level: "low", explanation: "Network access is common; review it alongside the app's purpose and other permissions." },
};

interface UploadResult {
  fileName: string;
  sizeBytes: number;
  sha256: string;
  message: string;
}

function profileFromAnalysis(result: ApkAnalysisResponse): ApkProfile {
  const permissions: PermissionFinding[] = result.findings.length > 0
    ? result.findings
    : result.permissions.map((name) => {
      const detail = explanations[name] ?? { level: "medium" as const, explanation: "Review this permission against the app's stated purpose." };
      return { name, ...detail };
    });
  return {
    id: "uploaded-analysis",
    name: result.fileName,
    packageName: result.packageName ?? "Package name unavailable",
    verdict: result.riskScore >= 75 ? "High risk" : result.riskScore >= 40 ? "Elevated risk" : "Lower risk",
    riskScore: result.riskScore,
    permissions,
    summary: result.notes.join(" ") || `Static manifest parsed by ${result.parser}. No code was executed.`,
  };
}

export default function ApkAnalyzer() {
  const [selectedId, setSelectedId] = useState(apkProfiles[0].id);
  const [uploadedProfile, setUploadedProfile] = useState<ApkProfile | null>(null);
  const [upload, setUpload] = useState<UploadResult | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const profile = uploadedProfile ?? apkProfiles.find((item) => item.id === selectedId) ?? apkProfiles[0];

  const inspectFile = async (file?: File) => {
    if (!file) return;
    setError("");
    setUpload(null);
    setUploadedProfile(null);
    if (!file.name.toLowerCase().endsWith(".apk")) {
      setError("Choose an .apk file. Only static APK inspection is supported.");
      return;
    }
    if (file.size > maxBytes) {
      setError("File exceeds the strict 50 MB limit. No file data was read or uploaded.");
      return;
    }
    setBusy(true);
    try {
      const digest = await crypto.subtle.digest("SHA-256", await file.arrayBuffer());
      const sha256 = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
      setUpload({ fileName: file.name, sizeBytes: file.size, sha256, message: "SHA-256 computed locally." });
      const result = await analyzeApk(file);
      if (result) {
        setUploadedProfile(profileFromAnalysis(result));
        setUpload({ fileName: result.fileName, sizeBytes: result.sizeBytes, sha256: result.sha256, message: `${result.parser} · static-only inspection · no code executed` });
      } else {
        setUpload((current) => current ? { ...current, message: "Backend unavailable. Hash computed locally; select a sample profile below for a full offline permission audit." } : current);
      }
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "The APK could not be inspected.");
    } finally {
      setBusy(false);
      if (inputRef.current) inputRef.current.value = "";
    }
  };

  return (
    <div className="fade-in space-y-5">
      <header className="flex flex-col justify-between gap-3 sm:flex-row sm:items-end"><div><p className="eyebrow">STATIC ANALYSIS / ANDROID PACKAGE</p><h1 className="mt-2 text-2xl font-bold text-white sm:text-3xl">APK permission analyzer</h1><p className="mt-1 text-sm text-slate-400">Inspect declared permissions only. Uploaded apps are never installed or executed.</p></div><div className="rounded-full border border-danger/20 bg-danger/5 px-3 py-2 font-mono text-[10px] text-danger">STATIC-ONLY · MAX 50 MB</div></header>
      <div className="grid gap-4 xl:grid-cols-[.9fr_1.1fr]">
        <div className="space-y-4">
          <section className="panel rounded-xl p-5">
            <div className="flex items-center justify-between"><div><p className="eyebrow">SAMPLE PERMISSION AUDITS</p><p className="mt-1 text-xs text-slate-500">Local demo profiles work offline</p></div><FileArchive size={17} className="text-cyan" /></div>
            <div className="mt-4 grid gap-2 sm:grid-cols-3 xl:grid-cols-1 2xl:grid-cols-3">
              {apkProfiles.map((item) => <button key={item.id} onClick={() => { setSelectedId(item.id); setUploadedProfile(null); }} className={`rounded-lg border p-3 text-left transition ${profile.id === item.id ? "border-cyan/35 bg-cyan/[.05]" : "border-white/5 bg-white/[.015] hover:border-white/15"}`}><span className="block text-xs font-bold text-slate-200">{item.name}</span><span className="mt-1 block font-mono text-[9px] text-slate-500">{item.packageName}</span><span className={`mt-2 inline-block font-mono text-[9px] ${item.riskScore > 75 ? "text-danger" : item.riskScore > 40 ? "text-amber" : "text-cyan"}`}>{item.riskScore}/100 RISK</span></button>)}
            </div>
          </section>
          <section
            onDragOver={(event) => { event.preventDefault(); setDragging(true); }}
            onDragLeave={() => setDragging(false)}
            onDrop={(event) => { event.preventDefault(); setDragging(false); void inspectFile(event.dataTransfer.files[0]); }}
            className={`panel rounded-xl border-dashed p-5 transition ${dragging ? "border-cyan/50 bg-cyan/[.04]" : ""}`}
          >
            <input ref={inputRef} type="file" accept=".apk,application/vnd.android.package-archive" className="hidden" onChange={(event) => void inspectFile(event.target.files?.[0])} />
            <div className="flex items-start gap-3"><div className="grid h-9 w-9 shrink-0 place-items-center rounded-lg border border-cyan/20 bg-cyan/5 text-cyan"><UploadCloud size={17} /></div><div className="min-w-0 flex-1"><p className="text-sm font-bold text-white">Inspect an APK</p><p className="mt-1 text-[11px] leading-relaxed text-slate-500">Drop a file here or choose it to calculate a local SHA-256 hash. Live backend parses the manifest; samples are fully available offline.</p></div></div>
            <button onClick={() => inputRef.current?.click()} disabled={busy} className="mt-4 flex w-full items-center justify-center gap-2 rounded-lg border border-white/10 bg-white/[.025] px-3 py-2.5 text-xs font-semibold text-slate-300 hover:border-cyan/30 hover:text-cyan disabled:opacity-50">{busy ? <><LoaderCircle size={14} className="animate-spin" /> Checking static manifest…</> : "Choose .apk file"}</button>
            {error && <p role="alert" className="mt-3 flex items-start gap-2 text-[11px] text-danger"><AlertOctagon size={14} className="shrink-0" />{error}</p>}
            {upload && <div className="mt-3 rounded-lg border border-cyan/10 bg-cyan/[.025] p-3"><div className="flex items-center gap-2 text-xs font-semibold text-cyan"><Fingerprint size={14} />{upload.fileName} · {(upload.sizeBytes / 1024 / 1024).toFixed(2)} MB</div><p className="mt-2 break-all font-mono text-[9px] leading-relaxed text-slate-500">SHA-256: {upload.sha256}</p><p className="mt-2 text-[10px] text-slate-400">{upload.message}</p></div>}
            <p className="mt-3 font-mono text-[9px] text-slate-600">SIZE LIMIT: 52,428,800 BYTES · FILE IS NOT STORED IN THE BROWSER</p>
          </section>
        </div>
        <section className="panel overflow-hidden rounded-xl">
          <div className="flex items-center justify-between border-b border-white/5 p-4"><div><p className="eyebrow">STATIC PERMISSION REPORT</p><p className="mt-1 text-xs text-slate-400">{profile.name}</p></div><Shield size={17} className="text-cyan" /></div>
          <div className="p-5">
            <div className="flex items-end justify-between"><div><p className="eyebrow">STATIC RISK INDICATOR</p><p className="mt-1 text-lg font-bold text-white">{profile.verdict}</p></div><span className={`mono text-2xl font-bold ${profile.riskScore >= 75 ? "text-danger" : profile.riskScore >= 40 ? "text-amber" : "text-cyan"}`}>{profile.riskScore}<span className="text-xs text-slate-500">/100</span></span></div>
            <div className="risk-bar mt-3 h-1 overflow-hidden rounded"><div className="h-full bg-ink/70" style={{ width: `${100 - profile.riskScore}%`, marginLeft: `${profile.riskScore}%` }} /></div>
            <p className="mt-3 text-xs leading-relaxed text-slate-400">{profile.summary}</p>
            <div className="mt-4 space-y-2">{profile.permissions.map((permission) => <div key={permission.name} className="flex gap-3 rounded-lg border border-white/5 bg-white/[.015] p-3"><div className="mt-0.5"><CheckCircle2 size={14} className={permission.level === "low" ? "text-cyan" : permission.level === "medium" ? "text-amber" : "text-danger"} /></div><div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><span className="font-mono text-[10px] text-slate-200">{permission.name}</span><span className={`font-mono text-[8px] uppercase ${permission.level === "low" ? "text-cyan" : permission.level === "medium" ? "text-amber" : "text-danger"}`}>{permission.level}</span></div><p className="mt-1 text-[10px] leading-relaxed text-slate-500">{permission.explanation}</p></div></div>)}</div>
          </div>
        </section>
      </div>
    </div>
  );
}
