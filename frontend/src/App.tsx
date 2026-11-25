import { lazy, Suspense, useEffect, useState } from "react";
import { Activity, AppWindow, ArrowUpRight, Bell, Boxes, ChevronRight, Fingerprint, Globe2, LayoutDashboard, MailWarning, Menu, Shield, X } from "lucide-react";
import { getScenarios } from "./services/apiClient";
import { phishingScenarios, threatCategories } from "./data/mockData";
import type { LearningProgress, ModuleId, PhishingScenario, ThreatId } from "./types/cyber";

const Hub = lazy(() => import("./components/modules/Hub"));
const PhishingLab = lazy(() => import("./components/modules/PhishingLab"));
const ApkAnalyzer = lazy(() => import("./components/modules/ApkAnalyzer"));
const Forensics = lazy(() => import("./components/modules/Forensics"));

const navigation: Array<{ id: ModuleId; label: string; icon: typeof LayoutDashboard }> = [
  { id: "hub", label: "Threat hub", icon: LayoutDashboard },
  { id: "phishing", label: "Phishing lab", icon: MailWarning },
  { id: "apk", label: "APK analyzer", icon: AppWindow },
  { id: "forensics", label: "Forensics", icon: Fingerprint },
];

const progressStorageKey = "sentinel-learning-progress";

function initialProgress(): LearningProgress {
  return {
    score: 620,
    streak: 4,
    lastActiveDate: new Date().toISOString().slice(0, 10),
    confidence: Object.fromEntries(threatCategories.map(({ id, score }) => [id, score])) as Record<ThreatId, number>,
    reportedScenarios: [],
    completedAssessments: [],
  };
}

function loadProgress(): LearningProgress {
  const fallback = initialProgress();
  try {
    const stored = window.localStorage.getItem(progressStorageKey);
    if (!stored) return fallback;
    const value: unknown = JSON.parse(stored);
    if (typeof value !== "object" || value === null) return fallback;
    const progress = value as Partial<LearningProgress>;
    if (
      typeof progress.score !== "number" ||
      !Number.isFinite(progress.score) ||
      typeof progress.streak !== "number" ||
      !Number.isFinite(progress.streak) ||
      typeof progress.lastActiveDate !== "string" ||
      typeof progress.confidence !== "object" ||
      progress.confidence === null ||
      !Array.isArray(progress.reportedScenarios) ||
      !Array.isArray(progress.completedAssessments)
    ) return fallback;

    const confidence = { ...fallback.confidence };
    for (const category of threatCategories) {
      const savedScore = progress.confidence[category.id];
      if (typeof savedScore === "number" && Number.isFinite(savedScore)) {
        confidence[category.id] = Math.max(0, Math.min(100, savedScore));
      }
    }

    return {
      score: Math.max(0, Math.min(1000, progress.score)),
      streak: Math.max(0, Math.floor(progress.streak)),
      lastActiveDate: progress.lastActiveDate,
      confidence,
      reportedScenarios: progress.reportedScenarios.filter((id): id is string => typeof id === "string"),
      completedAssessments: progress.completedAssessments.filter((id): id is string => typeof id === "string"),
    };
  } catch {
    return fallback;
  }
}

function recordLearningDay(progress: LearningProgress): Pick<LearningProgress, "streak" | "lastActiveDate"> {
  const today = new Date().toISOString().slice(0, 10);
  if (progress.lastActiveDate === today) return { streak: progress.streak, lastActiveDate: today };
  const yesterday = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
  return {
    streak: progress.lastActiveDate === yesterday ? progress.streak + 1 : 1,
    lastActiveDate: today,
  };
}

export default function App() {
  const [active, setActive] = useState<ModuleId>("hub");
  const [scenarios, setScenarios] = useState<PhishingScenario[]>(phishingScenarios);
  const [apiSource, setApiSource] = useState<"demo" | "api">("demo");
  const [progress, setProgress] = useState<LearningProgress>(loadProgress);
  const [mobileMenu, setMobileMenu] = useState(false);
  const [apiError, setApiError] = useState("");
  const [persistenceError, setPersistenceError] = useState("");

  useEffect(() => {
    let activeRequest = true;
    void getScenarios().then((result) => {
      if (!activeRequest) return;
      setScenarios(result.scenarios);
      setApiSource(result.source);
    }).catch((error: unknown) => {
      if (!activeRequest) return;
      setApiError(error instanceof Error ? error.message : "The scenario service could not be loaded.");
    });
    return () => { activeRequest = false; };
  }, []);

  useEffect(() => {
    try {
      window.localStorage.setItem(progressStorageKey, JSON.stringify(progress));
      setPersistenceError("");
    } catch {
      setPersistenceError("Learning progress could not be saved in this browser.");
    }
  }, [progress]);

  const onAssessment = (scenarioId: string, category: ThreatId, correct: boolean): boolean => {
    if (progress.completedAssessments.includes(scenarioId)) return false;
    setProgress((current) => {
      if (current.completedAssessments.includes(scenarioId)) return current;
      const activity = recordLearningDay(current);
      return {
        ...current,
        ...activity,
        score: Math.min(1000, current.score + (correct ? 10 : 0)),
        confidence: {
          ...current.confidence,
          [category]: Math.max(0, Math.min(100, current.confidence[category] + (correct ? 5 : -4))),
        },
        completedAssessments: [...current.completedAssessments, scenarioId],
      };
    });
    return true;
  };

  const onReportScenario = (scenarioId: string, category: ThreatId): boolean => {
    if (progress.reportedScenarios.includes(scenarioId)) return false;
    setProgress((current) => {
      if (current.reportedScenarios.includes(scenarioId)) return current;
      return {
        ...current,
        ...recordLearningDay(current),
        score: Math.min(1000, current.score + 40),
        confidence: {
          ...current.confidence,
          [category]: Math.min(100, current.confidence[category] + 3),
        },
        reportedScenarios: [...current.reportedScenarios, scenarioId],
      };
    });
    return true;
  };
  const selectModule = (id: ModuleId) => {
    setActive(id);
    setMobileMenu(false);
  };

  const content = active === "hub"
    ? <Hub score={progress.score} streak={progress.streak} confidence={progress.confidence} onNavigate={selectModule} />
    : active === "phishing"
      ? <PhishingLab
          scenarios={scenarios}
          reportedScenarios={progress.reportedScenarios}
          onAssessment={onAssessment}
          onReportScenario={onReportScenario}
        />
      : active === "apk"
        ? <ApkAnalyzer />
        : <Forensics />;

  return (
    <div className="min-h-screen bg-ink text-slate-100">
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-[246px] border-r border-white/[.06] bg-white lg:block">
        <div className="flex h-[72px] items-center gap-3 border-b border-white/[.06] px-5">
          <div className="grid h-9 w-9 place-items-center rounded-xl border border-cyan/20 bg-cyan/10 text-cyan"><Shield size={20} /></div>
          <div><p className="text-sm font-extrabold tracking-[.12em] text-white">SENTINEL</p><p className="font-mono text-[8px] tracking-[.18em] text-slate-600">CYBER AWARENESS</p></div>
        </div>
        <div className="px-4 pt-7"><p className="eyebrow px-3">COMMAND</p><nav className="mt-3 space-y-1">
          {navigation.map((item, index) => {
            const Icon = item.icon;
            return <button key={item.id} onClick={() => selectModule(item.id)} className={`group flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-left text-xs font-semibold transition ${active === item.id ? "border border-cyan/15 bg-cyan/[.07] text-cyan" : "border border-transparent text-slate-500 hover:bg-white/[.03] hover:text-slate-200"}`}><Icon size={16} /><span className="flex-1">{item.label}</span><span className={`font-mono text-[8px] ${active === item.id ? "text-cyan/60" : "text-slate-700"}`}>0{index + 1}</span></button>;
          })}
        </nav></div>
        <div className="absolute bottom-4 left-4 right-4 rounded-xl border border-white/[.06] bg-white/[.02] p-3">
          <div className="flex items-center gap-2"><Activity size={13} className="text-cyan" /><span className="eyebrow">ENVIRONMENT</span></div>
          <div className="mt-3 flex items-center justify-between"><span className="text-[10px] text-slate-500">Scenario source</span><span className="flex items-center gap-1.5 font-mono text-[9px] text-cyan"><i className="h-1.5 w-1.5 rounded-full bg-cyan" />{apiSource === "api" ? "LIVE API" : "LOCAL DEMO"}</span></div>
          <p className="mt-2 text-[9px] leading-relaxed text-slate-600">Training only · No live scanning or external links</p>
        </div>
      </aside>

      <div className="lg:pl-[246px]">
        <header className="sticky top-0 z-20 flex h-[68px] items-center justify-between border-b border-white/[.06] bg-white/95 px-4 backdrop-blur-xl sm:px-7">
          <div className="flex items-center gap-3">
            <button onClick={() => setMobileMenu((open) => !open)} className="rounded-lg border border-white/10 p-2 text-slate-400 lg:hidden" aria-label="Toggle navigation">{mobileMenu ? <X size={17} /> : <Menu size={17} />}</button>
            <div className="grid h-8 w-8 place-items-center rounded-lg border border-cyan/20 bg-cyan/10 text-cyan lg:hidden"><Shield size={16} /></div>
            <div className="hidden items-center gap-2 text-[10px] text-slate-600 sm:flex"><span>WORKSPACE</span><ChevronRight size={12} /><span className="text-slate-300">{navigation.find((item) => item.id === active)?.label.toUpperCase()}</span></div>
            <span className="text-xs font-bold tracking-wider text-white sm:hidden">SENTINEL</span>
          </div>
          <div className="flex items-center gap-3">
            <span className="hidden items-center gap-1.5 rounded-full border border-cyan/10 bg-cyan/[.035] px-2.5 py-1.5 font-mono text-[9px] text-cyan sm:flex"><span className="h-1.5 w-1.5 rounded-full bg-cyan" /> SAFE MODE</span>
            <button className="relative rounded-lg border border-white/[.07] p-2 text-slate-500 hover:text-slate-200" aria-label="Notifications"><Bell size={15} /><span className="absolute right-1.5 top-1.5 h-1.5 w-1.5 rounded-full bg-amber" /></button>
            <div className="grid h-8 w-8 place-items-center rounded-full border border-cyan/20 bg-cyan/10 text-[10px] font-bold text-cyan">AN</div>
          </div>
        </header>
        {mobileMenu && <div className="fixed inset-0 z-30 bg-slate-900/35 lg:hidden" onClick={() => setMobileMenu(false)}><nav onClick={(event) => event.stopPropagation()} className="w-72 border-r border-white/10 bg-white p-4 pt-6 shadow-2xl">{navigation.map((item) => { const Icon = item.icon; return <button key={item.id} onClick={() => selectModule(item.id)} className={`flex w-full items-center gap-3 rounded-lg px-3 py-3 text-left text-xs ${active === item.id ? "bg-cyan/10 text-cyan" : "text-slate-400"}`}><Icon size={16} />{item.label}</button>; })}</nav></div>}
        <main className="mx-auto max-w-[1500px] px-4 py-6 sm:px-7 sm:py-8">{apiError && <div role="alert" className="mb-4 rounded-lg border border-amber/20 bg-amber/5 px-4 py-3 text-xs text-amber">Scenario service returned an error: {apiError} · Local demo data remains available.</div>}{persistenceError && <div role="status" className="mb-4 rounded-lg border border-amber/20 bg-amber/5 px-4 py-3 text-xs text-amber">{persistenceError}</div>}<Suspense fallback={<div className="panel grid min-h-[360px] place-items-center rounded-xl text-xs text-slate-500">Loading secure training module…</div>}>{content}</Suspense></main>
        <footer className="flex flex-col justify-between gap-2 border-t border-white/[.05] px-4 py-4 text-[9px] text-slate-700 sm:flex-row sm:px-7"><span>© 2026 SENTINEL AWARENESS LAB · TRAINING ENVIRONMENT</span><span className="flex items-center gap-2"><Boxes size={11} /> Static analysis only <span className="text-slate-800">·</span><Globe2 size={11} /> Local demo-ready <ArrowUpRight size={10} /></span></footer>
      </div>
    </div>
  );
}
