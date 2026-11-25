import type { ApkProfile, PhishingScenario, ThreatCategory, UrlAnalysis } from "../types/cyber";

export const threatCategories: ThreatCategory[] = [
  { id: "email", label: "Email phishing", shortLabel: "EMAIL", color: "#c6284d", score: 64, description: "Impersonation and credential-harvesting messages." },
  { id: "qr", label: "QR / Smishing", shortLabel: "QR / SMS", color: "#a16207", score: 78, description: "QR codes and text messages that conceal destination links." },
  { id: "apk", label: "Malicious APKs", shortLabel: "APK", color: "#c6284d", score: 51, description: "Apps that request powerful permissions without a clear need." },
  { id: "oauth", label: "OAuth consent traps", shortLabel: "OAUTH", color: "#087e8b", score: 88, description: "Misleading app-consent screens asking for excessive access." },
];

export const phishingScenarios: PhishingScenario[] = [
  {
    id: "upi-refund",
    sender: "support@upi-refund-check.co",
    replyTo: "refund-desk@upi-helpdesk.support",
    senderName: "UPI Security Desk",
    subject: "Action needed: your ₹8,450 refund expires today",
    preview: "Confirm your account to release the pending refund.",
    category: "email",
    time: "09:41 AM",
    risk: "critical",
    redFlags: ["Lookalike sender domain", "Reply-To domain mismatch", "Urgency pressure", "Credential trap"],
    body: "A refund is waiting for your account. Verify your banking details within 30 minutes or the transaction will be cancelled.",
    linkText: "Review refund status",
  },
  {
    id: "qr-invite",
    sender: "events@office-gathering.info",
    senderName: "Team Events",
    subject: "Scan for today's all-hands room update",
    preview: "The meeting room changed. Scan this code to see the new location.",
    category: "qr",
    time: "09:18 AM",
    risk: "high",
    redFlags: ["Unexpected QR destination", "Unverified sender", "Redirect hidden by QR"],
    body: "Our room booking changed at the last minute. Scan the included code to confirm your attendance and open the updated agenda.",
    linkText: "Preview QR destination",
  },
  {
    id: "oauth-docs",
    sender: "notifications@cloud-docs-app.net",
    senderName: "Cloud Docs",
    subject: "A colleague shared a confidential document",
    preview: "Grant the new viewer access to continue.",
    category: "oauth",
    time: "Yesterday",
    risk: "high",
    redFlags: ["Unverified publisher", "Excessive account permissions", "Unexpected consent request"],
    body: "The requested document is ready. This app asks to read your contacts and maintain access to your account.",
    linkText: "Review app permissions",
  },
  {
    id: "login-clone",
    sender: "alerts@secure-account-check.com",
    senderName: "Account Protection",
    subject: "Unusual sign-in attempt blocked",
    preview: "Sign in to restore access to your account.",
    category: "email",
    time: "Yesterday",
    risk: "critical",
    redFlags: ["Spoofed sign-in domain", "Fear-based urgency", "Password capture page"],
    body: "We blocked a sign-in from a new device. Confirm your identity now to avoid a temporary account lock.",
    linkText: "Open secure sign-in",
  },
];

const finding = (name: string, level: ApkProfile["permissions"][number]["level"], explanation: string) => ({ name, level, explanation });

export const apkProfiles: ApkProfile[] = [
  {
    id: "fake-upi",
    name: "Fake UPI Update",
    packageName: "com.quickpay.update",
    verdict: "High risk",
    riskScore: 94,
    summary: "SMS access paired with overlay permissions can intercept one-time codes and imitate trusted app screens.",
    permissions: [
      finding("RECEIVE_SMS", "critical", "Can receive verification texts. Combined with other access, this may expose one-time codes."),
      finding("READ_SMS", "high", "Can read stored text messages, including financial alerts and verification codes."),
      finding("SYSTEM_ALERT_WINDOW", "high", "Can draw over other apps and imitate a trusted sign-in or payment screen."),
      finding("INTERNET", "low", "Network access is common; review it alongside the app's purpose and other permissions."),
    ],
  },
  {
    id: "qr-scanner",
    name: "QR Scanner Pro",
    packageName: "com.scan.master.pro",
    verdict: "Elevated risk",
    riskScore: 71,
    summary: "A scanner has a reasonable camera use, but contacts and accessibility access are not needed to read QR codes.",
    permissions: [
      finding("CAMERA", "low", "Expected for scanning QR codes when clearly disclosed."),
      finding("READ_CONTACTS", "high", "Can access your address book; a QR scanner normally has no need for this."),
      finding("BIND_ACCESSIBILITY_SERVICE", "critical", "Accessibility access can observe or control screen interactions; rarely justified for a scanner."),
      finding("INTERNET", "low", "Network access can send scanned links or data; inspect the privacy policy."),
    ],
  },
  {
    id: "clean-calculator",
    name: "Clean Calculator",
    packageName: "com.simple.tools.calculator",
    verdict: "Low risk",
    riskScore: 12,
    summary: "The requested capabilities are proportionate to a basic calculator in this sample profile.",
    permissions: [
      finding("VIBRATE", "low", "May provide haptic feedback when using calculator controls."),
    ],
  },
];

export const mockUrlAnalysis: UrlAnalysis = {
  normalizedUrl: "https://secure-account-check.com/session/verify",
  host: "secure-account-check.com",
  riskScore: 87,
  reasons: [
    "The host uses account-security wording that can create a false sense of trust.",
    "The URL contains a sign-in path and a verification action commonly used in credential lures.",
    "No live domain-age or reputation lookup was performed in offline demo mode.",
  ],
  hops: [
    { label: "Message link", detail: "secure-account-check.com/session/verify", status: "warning" },
    { label: "Host check", detail: "New or unverified domain signal (demo)", status: "danger" },
    { label: "TLS", detail: "HTTPS syntax only; certificate not checked offline", status: "warning" },
    { label: "Destination", detail: "Credential prompt pattern detected", status: "danger" },
  ],
  tls: "HTTPS requested; certificate validity was not checked offline.",
  domainAge: "Unavailable offline — demo reputation signal only.",
  authentication: "SPF / DKIM / DMARC require raw email headers; not inferred from a URL.",
};
