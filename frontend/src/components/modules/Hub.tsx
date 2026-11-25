import { ArrowUpRight, BadgeCheck, Bug, Flame, Fingerprint, MailWarning, Shield, ShieldAlert, Sparkles } from "lucide-react";
import { threatCategories } from "../../data/mockData";
import type { ThreatId } from "../../types/cyber";

interface HubProps {
  score: number;
  streak: number;
  confidence: Record<ThreatId, number>;
  onNavigate: (module: "phishing" | "apk" | "forensics") => void;
}

const threatIcons = [MailWarning, Fingerprint, ShieldAlert, Bug];

export default function Hub({ score, streak, confidence, onNavigate }: HubProps) {
  const categories = threatCategories.map((category) => ({ ...category, score: confidence[category.id] ?? category.score }));
  const weakest = [...categories].sort((a, b) => a.score - b.score)[0];
  const tier = score >= 850 ? "Sentinel" : score >= 700 ? "Vigilant" : score >= 500 ? "Aware" : "Getting started";

  return (
    <div className="fade-in space-y-6">
      <header className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
        <div>
          <p className="eyebrow">SECURITY AWARENESS / OVERVIEW</p>
          <h1 className="mt-2 text-3xl font-bold tracking-tight text-white">Your security, at a glance</h1>
          <p className="mt-2 max-w-2xl text-sm text-slate-400">Build everyday confidence against phishing, risky apps, and deceptive links.</p>
        </div>
        <div className="flex w-fit items-center gap-2 rounded-full border border-cyan/20 bg-cyan/5 px-3 py-2 text-[10px] font-semibold text-cyan">
          <span className="h-2 w-2 rounded-full bg-cyan" /> LEARNING ENVIRONMENT
        </div>
      </header>

      <section className="grid gap-4 md:grid-cols-3">
        <article className="panel rounded-2xl p-5 md:col-span-2">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="flex items-start gap-4">
              <div className="grid h-12 w-12 place-items-center rounded-2xl bg-cyan/10 text-cyan"><Shield size={23} /></div>
              <div><p className="eyebrow">RESILIENCE SCORE</p><p className="mt-1 text-4xl font-bold tracking-tight text-white">{score}<span className="ml-1 text-base font-medium text-slate-500">/ 1000</span></p><p className="mt-1 text-xs text-slate-400">Current level: <span className="font-semibold text-cyan">{tier}</span></p></div>
            </div>
            <div className="rounded-xl bg-amber/10 px-3 py-2 text-amber"><div className="flex items-center gap-2"><Flame size={17} /><span className="text-sm font-bold">{streak} days</span></div><p className="mt-1 text-[9px] font-semibold uppercase tracking-wide">Learning streak</p></div>
          </div>
          <div className="mt-6"><div className="mb-2 flex justify-between text-[10px] text-slate-500"><span>Progress to next level</span><span>{Math.min(100, Math.round(score / 10))}%</span></div><div className="h-2 overflow-hidden rounded-full bg-slate-100"><div className="h-full rounded-full bg-cyan transition-all" style={{ width: `${Math.min(100, score / 10)}%` }} /></div></div>
          <div className="mt-5 flex items-center gap-2 border-t border-white/10 pt-4 text-[11px] text-slate-400"><BadgeCheck size={15} className="text-cyan" /> Progress is saved locally in this browser.</div>
        </article>
        <article className="panel rounded-2xl p-5">
          <div className="flex items-center justify-between"><p className="eyebrow">RECOMMENDED NEXT STEP</p><Sparkles size={16} className="text-amber" /></div>
          <div className="mt-5 flex items-start gap-3"><div className="grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-danger/10 text-danger"><ShieldAlert size={18} /></div><div><h2 className="text-sm font-bold text-white">Practice {weakest.label}</h2><p className="mt-1 text-xs leading-relaxed text-slate-400">This is your lowest-confidence topic at {weakest.score}%. A short exercise can help build confidence.</p></div></div>
          <button onClick={() => onNavigate(weakest.id === "apk" ? "apk" : weakest.id === "oauth" ? "forensics" : "phishing")} className="mt-5 flex w-full items-center justify-between rounded-xl bg-cyan px-4 py-3 text-xs font-bold text-ink transition hover:bg-cyan/90">Start a quick exercise <ArrowUpRight size={15} /></button>
        </article>
      </section>

      <section>
        <div className="mb-3 flex items-end justify-between"><div><p className="eyebrow">YOUR TOPICS</p><h2 className="mt-1 text-lg font-bold text-white">Confidence by topic</h2></div><span className="hidden text-[10px] text-slate-500 sm:block">Select a topic for a recommended activity</span></div>
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          {categories.map((category, index) => {
            const Icon = threatIcons[index] ?? ShieldAlert;
            const target = category.id === "apk" ? "apk" : category.id === "oauth" ? "forensics" : "phishing";
            return <button key={category.id} onClick={() => onNavigate(target)} className="panel rounded-2xl p-4 text-left transition hover:-translate-y-0.5 hover:border-cyan/30">
              <div className="flex items-start justify-between"><div className="grid h-10 w-10 place-items-center rounded-xl" style={{ backgroundColor: `${category.color}15`, color: category.color }}><Icon size={18} /></div><ArrowUpRight size={14} className="text-slate-400" /></div>
              <p className="mt-4 text-sm font-bold text-white">{category.label}</p><p className="mt-1 min-h-8 text-[10px] leading-relaxed text-slate-400">{category.description}</p>
              <div className="mt-4 flex items-center justify-between"><span className="text-2xl font-bold text-white">{category.score}<span className="ml-0.5 text-xs font-medium text-slate-500">%</span></span><span className="font-mono text-[9px] font-semibold uppercase tracking-wide" style={{ color: category.color }}>{category.score < 60 ? "Practice suggested" : category.score < 75 ? "Building" : "On track"}</span></div>
              <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-slate-100"><div className="h-full rounded-full" style={{ width: `${category.score}%`, backgroundColor: category.color }} /></div>
            </button>;
          })}
        </div>
      </section>
    </div>
  );
}
