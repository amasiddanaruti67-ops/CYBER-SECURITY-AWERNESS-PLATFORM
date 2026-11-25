from __future__ import annotations

import hashlib
import io
import ipaddress
import os
import tempfile
import unicodedata
import zipfile
from typing import Literal
from urllib.parse import parse_qs, urlsplit
from xml.etree import ElementTree

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field

MAX_APK_BYTES = 50 * 1024 * 1024
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_ZIP_ENTRIES = 10_000
ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

PERMISSION_EXPLANATIONS: dict[str, tuple[str, str]] = {
    "RECEIVE_SMS": ("critical", "Can receive verification texts; combined with other access, this may expose one-time codes."),
    "READ_SMS": ("high", "Can read stored text messages, including financial alerts and verification codes."),
    "SEND_SMS": ("high", "Can send texts, potentially incurring charges or impersonating the user."),
    "BIND_ACCESSIBILITY_SERVICE": ("critical", "Accessibility access can observe or control screen interactions; rarely justified."),
    "SYSTEM_ALERT_WINDOW": ("high", "Can draw over other apps and imitate a trusted sign-in or payment screen."),
    "READ_CONTACTS": ("high", "Can access the address book; consider whether the app's purpose requires it."),
    "REQUEST_INSTALL_PACKAGES": ("high", "Can request installation of other packages outside a normal app-store flow."),
    "INTERNET": ("low", "Network access is common; review it alongside the app's purpose and other permissions."),
    "CAMERA": ("low", "Can access the camera; verify that this matches the app's stated functionality."),
    "VIBRATE": ("low", "May provide haptic feedback."),
}
RISK_WEIGHT = {"low": 3, "medium": 12, "high": 24, "critical": 34}

app = FastAPI(
    title="Sentinel Cyber Awareness API",
    version="1.0.0",
    description="Training scenarios and static-only URL/APK analysis. No submitted app is executed.",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

SCENARIOS = [
    {
        "id": "upi-refund",
        "sender": "support@upi-refund-check.co",
        "replyTo": "refund-desk@upi-helpdesk.support",
        "senderName": "UPI Security Desk",
        "subject": "Action needed: your ₹8,450 refund expires today",
        "preview": "Confirm your account to release the pending refund.",
        "category": "email",
        "time": "09:41 AM",
        "risk": "critical",
        "redFlags": ["Lookalike sender domain", "Reply-To domain mismatch", "Urgency pressure", "Credential trap"],
        "body": "A refund is waiting for your account. Verify your banking details within 30 minutes or the transaction will be cancelled.",
        "linkText": "Review refund status",
    },
    {
        "id": "qr-invite",
        "sender": "events@office-gathering.info",
        "senderName": "Team Events",
        "subject": "Scan for today's all-hands room update",
        "preview": "The meeting room changed. Scan this code to see the new location.",
        "category": "qr",
        "time": "09:18 AM",
        "risk": "high",
        "redFlags": ["Unexpected QR destination", "Unverified sender", "Redirect hidden by QR"],
        "body": "Our room booking changed at the last minute. Scan the included code to confirm your attendance and open the updated agenda.",
        "linkText": "Preview QR destination",
    },
    {
        "id": "oauth-docs",
        "sender": "notifications@cloud-docs-app.net",
        "senderName": "Cloud Docs",
        "subject": "A colleague shared a confidential document",
        "preview": "Grant the new viewer access to continue.",
        "category": "oauth",
        "time": "Yesterday",
        "risk": "high",
        "redFlags": ["Unverified publisher", "Excessive account permissions", "Unexpected consent request"],
        "body": "The requested document is ready. This app asks to read your contacts and maintain access to your account.",
        "linkText": "Review app permissions",
    },
    {
        "id": "login-clone",
        "sender": "alerts@secure-account-check.com",
        "senderName": "Account Protection",
        "subject": "Unusual sign-in attempt blocked",
        "preview": "Sign in to restore access to your account.",
        "category": "email",
        "time": "Yesterday",
        "risk": "critical",
        "redFlags": ["Spoofed sign-in domain", "Fear-based urgency", "Password capture page"],
        "body": "We blocked a sign-in from a new device. Confirm your identity now to avoid a temporary account lock.",
        "linkText": "Open secure sign-in",
    },
]


def permission_finding(permission: str) -> dict[str, str]:
    short_name = permission.rsplit(".", 1)[-1]
    level, explanation = PERMISSION_EXPLANATIONS.get(
        short_name,
        ("medium", "Review this permission against the app's stated purpose."),
    )
    return {"name": short_name, "level": level, "explanation": explanation}


APK_PROFILES = [
    {
        "id": "fake-upi",
        "name": "Fake UPI Update",
        "packageName": "com.quickpay.update",
        "verdict": "High risk",
        "riskScore": 94,
        "summary": "SMS access paired with overlay permissions can intercept one-time codes and imitate trusted app screens.",
        "permissions": [
            permission_finding("RECEIVE_SMS"),
            permission_finding("READ_SMS"),
            permission_finding("SYSTEM_ALERT_WINDOW"),
            permission_finding("INTERNET"),
        ],
    },
    {
        "id": "qr-scanner",
        "name": "QR Scanner Pro",
        "packageName": "com.scan.master.pro",
        "verdict": "Elevated risk",
        "riskScore": 71,
        "summary": "A scanner has a reasonable camera use, but contacts and accessibility access are not needed to read QR codes.",
        "permissions": [
            permission_finding("CAMERA"),
            permission_finding("READ_CONTACTS"),
            permission_finding("BIND_ACCESSIBILITY_SERVICE"),
            permission_finding("INTERNET"),
        ],
    },
    {
        "id": "clean-calculator",
        "name": "Clean Calculator",
        "packageName": "com.simple.tools.calculator",
        "verdict": "Low risk",
        "riskScore": 12,
        "summary": "The requested capabilities are proportionate to a basic calculator in this sample profile.",
        "permissions": [permission_finding("VIBRATE")],
    },
]


class SimulationEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scenarioId: str = Field(min_length=1, max_length=80)
    event: Literal["SENT", "OPENED", "CLICKED", "REPORTED"]


class UrlRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str = Field(min_length=1, max_length=2048)


event_counts: dict[tuple[str, str], int] = {}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "sentinel-awareness-api"}


@app.get("/api/scenarios")
def get_scenarios() -> dict[str, list[dict]]:
    return {"scenarios": SCENARIOS, "apkProfiles": APK_PROFILES}


@app.post("/api/events/simulation", status_code=201)
def record_simulation_event(event: SimulationEvent) -> dict[str, str]:
    if event.scenarioId not in {scenario["id"] for scenario in SCENARIOS}:
        raise HTTPException(status_code=404, detail="Unknown training scenario.")
    key = (event.scenarioId, event.event)
    event_counts[key] = event_counts.get(key, 0) + 1
    return {"status": "recorded", "scenarioId": event.scenarioId, "event": event.event}


def _url_analysis(raw_url: str) -> dict:
    candidate = raw_url.strip()
    if "://" not in candidate:
        candidate = "https://" + candidate
    try:
        parsed = urlsplit(candidate)
        hostname = parsed.hostname
        if parsed.scheme not in {"http", "https"} or not hostname:
            raise ValueError("Unsupported URL.")
        _ = parsed.port
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Enter a valid http or https URL.") from exc

    reasons: list[str] = []
    risk = 4
    try:
        ascii_host = hostname.encode("idna").decode("ascii").lower()
        unicode_host = ascii_host.encode("ascii").decode("idna")
    except UnicodeError:
        ascii_host, unicode_host = hostname.lower(), hostname
        reasons.append("The host could not be normalized with IDNA.")
        risk += 24

    if "xn--" in ascii_host:
        reasons.append(f"Punycode label detected; displayed Unicode form is {unicode_host}.")
        risk += 34
    scripts = {
        unicodedata.name(char, "").split(" ")[0]
        for char in unicode_host
        if char.isalpha() and unicodedata.name(char, "").split(" ")[0] not in {"LATIN", "COMMON"}
    }
    if scripts:
        reasons.append("The hostname contains non-Latin characters; visually similar characters may be used in homographs.")
        risk += 22
    try:
        ipaddress.ip_address(hostname)
        reasons.append("The URL uses a literal IP address instead of a recognizable domain.")
        risk += 20
    except ValueError:
        pass

    if parsed.username or parsed.password:
        reasons.append("The URL includes user-info before the host, which can disguise the actual destination.")
        risk += 25
    if len(hostname.split(".")) > 4:
        reasons.append("The hostname has many subdomain levels; verify the registrable domain carefully.")
        risk += 10
    if any(term in (hostname + parsed.path).lower() for term in ("login", "verify", "secure", "account", "update", "refund")):
        reasons.append("Account, verification, or refund wording can be used to create urgency or imply trust.")
        risk += 18

    query = parse_qs(parsed.query)
    redirect_keys = {"redirect", "redirect_uri", "next", "return", "continue", "url", "target"}
    for key in query:
        if key.lower() in redirect_keys:
            reasons.append(f"Redirect-like query parameter detected: {key}. Its destination was not followed.")
            risk += 12
            break
    if not reasons:
        reasons.append("No high-confidence URL structure warning was found by these static heuristics.")

    safe_host = ascii_host
    hops = [
        {"label": "Submitted URL", "detail": f"{parsed.scheme}://{safe_host}{parsed.path or '/'}", "status": "safe"},
        {"label": "Host normalization", "detail": unicode_host if unicode_host != ascii_host else "No Punycode conversion detected", "status": "danger" if "xn--" in ascii_host or scripts else "safe"},
        {"label": "Redirect parameters", "detail": "Present but not followed" if any(key.lower() in redirect_keys for key in query) else "No common redirect parameter detected", "status": "warning" if any(key.lower() in redirect_keys for key in query) else "safe"},
        {"label": "Transport", "detail": "HTTPS requested; certificate not checked" if parsed.scheme == "https" else "HTTP is not encrypted", "status": "warning" if parsed.scheme == "https" else "danger"},
    ]
    return {
        "normalizedUrl": candidate,
        "host": ascii_host,
        "riskScore": min(100, risk),
        "reasons": reasons,
        "hops": hops,
        "tls": "HTTPS requested; this static endpoint does not connect to or validate a certificate." if parsed.scheme == "https" else "HTTP URL; transport is not encrypted.",
        "domainAge": "Not checked; no WHOIS or external reputation lookup is performed.",
        "authentication": "SPF / DKIM / DMARC require email headers and cannot be inferred from a URL.",
    }


@app.post("/api/analyze/url")
def analyze_url(request: UrlRequest) -> dict:
    return _url_analysis(request.url)


def _manifest_from_xml(xml_bytes: bytes) -> tuple[str | None, list[str]]:
    root = ElementTree.fromstring(xml_bytes)
    package_name = root.attrib.get("package")
    permissions: list[str] = []
    for node in root.iter():
        if node.tag.rsplit("}", 1)[-1] in {"uses-permission", "uses-permission-sdk-23", "permission"}:
            name = node.attrib.get(f"{ANDROID_NS}name") or node.attrib.get("android:name")
            if name:
                permissions.append(name)
    return package_name, sorted(set(permissions))


def _androguard_parse(data: bytes) -> tuple[str | None, list[str]] | None:
    try:
        from androguard.core.apk import APK
    except (ImportError, OSError):
        return None

    path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as temporary:
            temporary.write(data)
            path = temporary.name
        parsed_apk = APK(path, skip_analysis=True)
        package_name = parsed_apk.get_package()
        permissions = parsed_apk.get_permissions()
        if isinstance(package_name, str) and isinstance(permissions, (list, tuple, set)):
            normalized = sorted({item for item in permissions if isinstance(item, str)})
            if package_name or normalized:
                return package_name or None, normalized
    except Exception:
        return None
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass
    return None


def _permission_risk(permissions: list[str]) -> int:
    short_names = {permission.rsplit(".", 1)[-1] for permission in permissions}
    risk = min(45, sum(RISK_WEIGHT.get(PERMISSION_EXPLANATIONS.get(name, ("medium", ""))[0], 12) for name in short_names))
    if "RECEIVE_SMS" in short_names and "SYSTEM_ALERT_WINDOW" in short_names:
        risk += 42
    if "BIND_ACCESSIBILITY_SERVICE" in short_names and ({"READ_SMS", "READ_CONTACTS", "SYSTEM_ALERT_WINDOW"} & short_names):
        risk += 38
    return min(100, risk)


@app.post("/api/analyze/apk")
async def analyze_apk(file: UploadFile = File(...)) -> dict:
    file_name = file.filename or ""
    if not file_name.lower().endswith(".apk"):
        raise HTTPException(status_code=415, detail="Only .apk files are accepted.")

    digest = hashlib.sha256()
    chunks: list[bytes] = []
    size = 0
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        size += len(chunk)
        if size > MAX_APK_BYTES:
            await file.close()
            raise HTTPException(status_code=413, detail="APK exceeds the 50 MB size limit.")
        digest.update(chunk)
        chunks.append(chunk)
    data = b"".join(chunks)
    await file.close()
    if not data:
        raise HTTPException(status_code=400, detail="The uploaded APK is empty.")

    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
            entries = archive.infolist()
            if len(entries) > MAX_ZIP_ENTRIES:
                raise HTTPException(status_code=400, detail="APK contains too many ZIP entries for safe inspection.")
            manifest = archive.getinfo("AndroidManifest.xml")
            if manifest.file_size > MAX_MANIFEST_BYTES:
                raise HTTPException(status_code=400, detail="Android manifest exceeds the safe parsing limit.")
            if manifest.compress_size and manifest.file_size / manifest.compress_size > 250:
                raise HTTPException(status_code=400, detail="Android manifest compression ratio exceeds the safe parsing limit.")
            manifest_bytes = archive.open(manifest, "r").read(MAX_MANIFEST_BYTES + 1)
            if len(manifest_bytes) > MAX_MANIFEST_BYTES:
                raise HTTPException(status_code=400, detail="Android manifest exceeds the safe parsing limit.")
    except KeyError as exc:
        raise HTTPException(status_code=400, detail="AndroidManifest.xml was not found in the APK.") from exc
    except zipfile.BadZipFile as exc:
        raise HTTPException(status_code=400, detail="The uploaded file is not a valid APK/ZIP archive.") from exc

    parsed = _androguard_parse(data)
    parser = "Androguard" if parsed else "Safe XML fallback"
    notes: list[str] = []
    package_name: str | None = None
    permissions: list[str] = []
    if parsed:
        package_name, permissions = parsed
    else:
        try:
            package_name, permissions = _manifest_from_xml(manifest_bytes)
        except (ElementTree.ParseError, UnicodeDecodeError, ValueError):
            notes.append("Manifest is binary or unsupported by the XML fallback; permission results may be incomplete.")
            parser = "ZIP safety checks only"

    findings = [permission_finding(permission) for permission in permissions]
    if not permissions:
        notes.append("No readable declared permissions were extracted; this is not proof the APK is safe.")
    notes.append("Static manifest inspection only. No APK code was executed.")
    return {
        "fileName": file_name,
        "sha256": digest.hexdigest(),
        "sizeBytes": size,
        "packageName": package_name,
        "permissions": [item["name"] for item in findings],
        "findings": findings,
        "riskScore": _permission_risk(permissions),
        "parser": parser,
        "notes": notes,
    }
