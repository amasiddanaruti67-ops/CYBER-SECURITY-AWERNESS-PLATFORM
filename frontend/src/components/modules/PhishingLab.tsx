import DOMPurify from "dompurify";
import { useEffect, useMemo, useState } from "react";
import { AlertTriangle, ArrowLeft, ArrowUpRight, Check, Clock3, Eye, Flag, Mail, ShieldCheck, X } from "lucide-react";
import { recordSimulationEvent } from "../../services/apiClient";
import type { PhishingScenario, SimulationEventType, ThreatId } from "../../types/cyber";

interface PhishingLabProps {
  scenarios: PhishingScenario[];
  reportedScenarios: string[];
  onAssessment: (scenarioId: string, category: ThreatId, correct: boolean) => boolean;
  onReportScenario: (scenarioId: string, category: ThreatId) => boolean;
}

export default function PhishingLab({ scenarios, reportedScenarios, onAssessment, onReportScenario }: PhishingLabProps) {
  const [activeId, setActiveId] = useState(scenarios[0]?.id ?? "");
  const [overlay, setOverlay] = useState(false);
  const [answer, setAnswer] = useState<boolean | null>(null);
  const [assessmentRecorded, setAssessmentRecorded] = useState(true);
  const [secondsLeft, setSecondsLeft] = useState(60);
  const scenario = scenarios.find((item) => item.id === activeId) ?? scenarios[0];
  const safeBody = useMemo(() => DOMPurify.sanitize(scenario?.body ?? "", { ALLOWED_TAGS: [], ALLOWED_ATTR: [] }), [scenario?.body]);

  useEffect(() => {
    if (scenario) void recordSimulationEvent({ scenarioId: scenario.id, event: "OPENED" });
  }, [scenario?.id]);

  useEffect(() => {
    if (!overlay || answer !== null) return;
    const intervalId = window.setInterval(() => {
      setSecondsLeft((remaining) => {
        if (remaining <= 1) {
          window.clearInterval(intervalId);
          setOverlay(false);
          return 0;
        }
        return remaining - 1;
      });
    }, 1000);
    return () => window.clearInterval(intervalId);
  }, [overlay, answer]);

  if (!scenario) return <div className="panel rounded-xl p-8 text-slate-400">No training scenarios are available.</div>;

  const log = (event: SimulationEventType) => { void recordSimulationEvent({ scenarioId: scenario.id, event }); };
  const openXray = (followedLure: boolean) => {
    setSecondsLeft(60);
    setOverlay(true);
    setAnswer(null);
    if (followedLure) log("CLICKED");
  };
  const report = () => {
    if (reportedScenarios.includes(scenario.id)) return;
    if (!onReportScenario(scenario.id, scenario.category)) return;
    log("REPORTED");
  };
  const chooseAnswer = (correct: boolean) => {
    setAnswer(correct);
    setAssessmentRecorded(onAssessment(scenario.id, scenario.category, correct));
  };

  return (
    <div className="fade-in space-y-5">
      <header className="flex flex-col justify-between gap-3 sm:flex-row sm:items-end"><div><p className="eyebrow">TRAINING MODULE / SOCIAL ENGINEERING</p><h1 className="mt-2 text-2xl font-bold text-white sm:text-3xl">Phishing lab</h1><p className="mt-1 text-sm text-slate-400">Inspect the signals. All messages and links are simulated.</p></div><div className="rounded-full border border-amber/20 bg-amber/5 px-3 py-2 font-mono text-[10px] text-amber">SAFE SANDBOX · NO CREDENTIALS REQUESTED</div></header>
      <div className="grid gap-4 xl:grid-cols-[320px_1fr]">
        <aside className="panel overflow-hidden rounded-xl">
          <div className="flex items-center justify-between border-b border-white/5 px-4 py-3"><span className="eyebrow">SIMULATED INBOX</span><span className="mono text-[10px] text-slate-500">{scenarios.length} MESSAGES</span></div>
          {scenarios.map((item) => (
            <button key={item.id} onClick={() => setActiveId(item.id)} className={`w-full border-b border-white/[.04] p-4 text-left transition hover:bg-white/[.025] ${item.id === scenario.id ? "bg-cyan/[.045] shadow-[inset_2px_0_#00f0ff]" : ""}`}>
              <div className="flex items-center justify-between gap-3"><span className="truncate text-xs font-semibold text-slate-200">{item.senderName}</span><span className="shrink-0 font-mono text-[9px] text-slate-600">{item.time}</span></div>
              <p className="mt-1 truncate text-[11px] text-slate-400">{item.subject}</p>
              <div className="mt-2 flex items-center justify-between"><span className="truncate font-mono text-[9px] text-slate-600">{item.sender}</span>{reportedScenarios.includes(item.id) && <Check size={13} className="text-cyan" />}</div>
            </button>
          ))}
          <div className="p-4 text-[10px] leading-relaxed text-slate-500"><Eye size={13} className="mb-2 text-cyan" /> Hover, pause, then verify the sender and destination before acting.</div>
        </aside>
        <section className="panel min-w-0 overflow-hidden rounded-xl">
          <div className="flex items-center justify-between border-b border-white/5 px-5 py-3"><div className="flex items-center gap-2 text-xs text-slate-400"><Mail size={14} className="text-cyan" /> Message preview</div><span className={`rounded border px-2 py-1 font-mono text-[9px] uppercase ${scenario.risk === "critical" ? "border-danger/30 bg-danger/5 text-danger" : "border-amber/30 bg-amber/5 text-amber"}`}>{scenario.risk} SIGNAL</span></div>
          <div className="p-5 sm:p-7">
            <h2 className="text-lg font-bold text-white">{scenario.subject}</h2>
            <div className="mt-4 space-y-1 text-xs text-slate-400"><p><span className="inline-block w-12 text-slate-600">FROM</span> {scenario.senderName} &lt;{scenario.sender}&gt;</p>{scenario.replyTo && <p><span className="inline-block w-12 text-slate-600">REPLY</span> {scenario.replyTo}</p>}<p><span className="inline-block w-12 text-slate-600">TO</span> analyst@sentinel.training</p></div>
            <div className="my-6 h-px bg-white/5" />
            <div className="max-w-2xl text-sm leading-7 text-slate-300">{safeBody}</div>
            <div className="mt-6 flex flex-wrap gap-3">
              <button onClick={() => openXray(true)} className="inline-flex items-center gap-2 rounded-lg border border-danger/30 bg-danger/10 px-4 py-2.5 text-xs font-bold text-danger transition hover:bg-danger/15"><ArrowUpRight size={14} /> {scenario.linkText}</button>
              <button onClick={report} disabled={reportedScenarios.includes(scenario.id)} className="inline-flex items-center gap-2 rounded-lg border border-cyan/25 bg-cyan/5 px-4 py-2.5 text-xs font-bold text-cyan disabled:cursor-default disabled:opacity-60"><Flag size={14} /> {reportedScenarios.includes(scenario.id) ? "Reported · +40 pts" : "Report Phish · +40 pts"}</button>
            </div>
            <div className="mt-8 rounded-xl border border-white/5 bg-slate-50 p-4 sm:p-5">
              <div className="flex items-start gap-3"><div className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-white/5 text-slate-400"><ShieldCheck size={16} /></div><div><p className="text-xs font-bold text-slate-200">Safe interaction checkpoint</p><p className="mt-1 text-[11px] text-slate-500">No credentials or personal information are requested. Continue to the X-Ray lesson to review the warning signs.</p></div></div>
              <button onClick={() => openXray(false)} className="mt-4 rounded-lg bg-cyan px-4 py-2.5 text-xs font-bold text-ink transition hover:bg-cyan/80">Continue safe simulation</button>
            </div>
          </div>
        </section>
      </div>

      {overlay && <div className="fixed inset-0 z-50 grid place-items-center bg-black/75 p-4 backdrop-blur-sm" role="dialog" aria-modal="true" aria-labelledby="xray-title">
        <div className="panel scanline fade-in max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-2xl">
          <div className="flex items-start justify-between border-b border-white/5 p-5"><div className="flex gap-3"><div className="grid h-10 w-10 place-items-center rounded-xl border border-danger/20 bg-danger/10 text-danger"><AlertTriangle size={19} /></div><div><p className="eyebrow text-danger">POINT-OF-CLICK X-RAY</p><h2 id="xray-title" className="mt-1 text-lg font-bold text-white">Pause. Inspect. Protect.</h2></div></div><button onClick={() => setOverlay(false)} aria-label="Close X-Ray" className="rounded-lg p-2 text-slate-500 hover:bg-white/5 hover:text-white"><X size={17} /></button></div>
          <div className="grid gap-5 p-5 md:grid-cols-[1fr_0.85fr]">
            <div><p className="eyebrow">SIGNALS FOUND</p><div className="mt-3 space-y-2">{scenario.redFlags.map((flag) => <div key={flag} className="flex items-center gap-2 rounded-lg border border-danger/10 bg-danger/[.04] p-2.5 text-xs text-slate-300"><AlertTriangle size={13} className="shrink-0 text-danger" />{flag}</div>)}</div><div className="mt-4 rounded-lg border border-white/5 bg-white/[.02] p-3"><p className="font-mono text-[9px] text-slate-600">SIMULATED DESTINATION</p><p className="mt-1 break-all font-mono text-[11px] text-danger">https://{scenario.sender.split("@")[1]}/verify-account</p><p className="mt-2 text-[10px] leading-relaxed text-slate-500">The displayed destination is a training example only. No link is opened.</p></div></div>
            <div className="rounded-xl border border-cyan/15 bg-cyan/[.03] p-4"><div className="flex items-center gap-2 text-cyan"><Clock3 size={15} /><span className="eyebrow text-cyan">60-SECOND MICRO-DRILL · {secondsLeft}s</span></div><p className="mt-3 text-sm font-semibold text-white">What is the safest next step?</p><div className="mt-3 space-y-2"><button disabled={answer !== null} onClick={() => chooseAnswer(false)} className="w-full rounded-lg border border-white/10 p-2.5 text-left text-[11px] text-slate-400 hover:border-white/20 disabled:cursor-default disabled:opacity-60">Click quickly before the offer expires</button><button disabled={answer !== null} onClick={() => chooseAnswer(true)} className="w-full rounded-lg border border-white/10 p-2.5 text-left text-[11px] text-slate-400 hover:border-cyan/30 hover:text-cyan disabled:cursor-default disabled:opacity-60">Verify through the official app or a known contact</button></div>{answer !== null && <p className={`mt-3 text-[11px] leading-relaxed ${answer ? "text-cyan" : "text-amber"}`}>{answer ? `Correct. Use a trusted channel, not the message link.${assessmentRecorded ? " +10 points." : " This lesson was already completed."}` : "Not quite. Urgency is a manipulation signal; verify independently."}</p>}</div>
          </div>
          <div className="flex justify-end border-t border-white/5 p-4"><button onClick={() => setOverlay(false)} className="inline-flex items-center gap-2 rounded-lg border border-white/10 px-3 py-2 text-xs text-slate-300 hover:bg-white/5"><ArrowLeft size={13} /> Back to message</button></div>
        </div>
      </div>}
    </div>
  );
}
