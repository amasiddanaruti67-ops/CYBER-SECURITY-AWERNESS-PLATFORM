import type { UrlAnalysis } from "../../types/cyber";

export default function TrustChain({ analysis }: { analysis: UrlAnalysis }) {
  return (
    <ol className="space-y-0">
      {analysis.hops.map((hop, index) => {
        const tone = hop.status === "danger" ? "border-danger bg-danger text-white" : hop.status === "warning" ? "border-amber bg-amber text-white" : "border-cyan bg-cyan text-white";
        return (
          <li className="flex gap-3" key={`${hop.label}-${index}`}>
            <div className="flex w-7 shrink-0 flex-col items-center">
              <span className={`trust-step grid h-7 w-7 place-items-center rounded-full border text-[10px] font-bold ${tone}`}>{String(index + 1).padStart(2, "0")}</span>
              {index < analysis.hops.length - 1 && <span className="my-1 min-h-7 w-px flex-1 bg-slate-200" />}
            </div>
            <div className="min-w-0 flex-1 pb-5">
              <p className="text-xs font-semibold text-slate-800">{hop.label}</p>
              <p className="mt-1 break-all font-mono text-[10px] leading-relaxed text-slate-500">{hop.detail}</p>
            </div>
          </li>
        );
      })}
    </ol>
  );
}
