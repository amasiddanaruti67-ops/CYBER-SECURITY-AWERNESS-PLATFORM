export type ModuleId = "hub" | "phishing" | "apk" | "forensics";
export type ThreatId = "email" | "qr" | "apk" | "oauth";
export type SimulationEventType = "SENT" | "OPENED" | "CLICKED" | "REPORTED";
export type RiskLevel = "low" | "medium" | "high" | "critical";

export interface ThreatCategory {
  id: ThreatId;
  label: string;
  shortLabel: string;
  color: string;
  score: number;
  description: string;
}

export interface PhishingScenario {
  id: string;
  sender: string;
  replyTo?: string;
  senderName: string;
  subject: string;
  preview: string;
  category: ThreatId;
  time: string;
  risk: RiskLevel;
  redFlags: string[];
  body: string;
  linkText: string;
}

export interface PermissionFinding {
  name: string;
  level: RiskLevel;
  explanation: string;
}

export interface ApkProfile {
  id: string;
  name: string;
  packageName: string;
  verdict: string;
  riskScore: number;
  permissions: PermissionFinding[];
  summary: string;
}

export interface UrlAnalysis {
  normalizedUrl: string;
  host: string;
  riskScore: number;
  reasons: string[];
  hops: Array<{ label: string; detail: string; status: "safe" | "warning" | "danger" }>;
  tls: string;
  domainAge: string;
  authentication: string;
}

export interface SimulationEvent {
  scenarioId: string;
  event: SimulationEventType;
}

export interface LearningProgress {
  score: number;
  streak: number;
  lastActiveDate: string;
  confidence: Record<ThreatId, number>;
  reportedScenarios: string[];
  completedAssessments: string[];
}

export interface ApkAnalysisResponse {
  fileName: string;
  sha256: string;
  sizeBytes: number;
  packageName: string | null;
  permissions: string[];
  findings: PermissionFinding[];
  riskScore: number;
  parser: string;
  notes: string[];
}
