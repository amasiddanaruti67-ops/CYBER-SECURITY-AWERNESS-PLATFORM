# Sentinel Cyber Awareness Platform

An integrated awareness and static-analysis app for simulated phishing training, URL and email-header forensics, Android APK permission review, and adaptive micro-learning.

## Features

- **Phishing lab:** interactive, simulated scenarios and short learning drills. It does not send emails, collect credentials, or open message links.
- **URL and email forensics:** static URL heuristics and local analysis of pasted email headers. No DNS, WHOIS, reputation, or redirect lookups are performed.
- **APK analyzer:** reviews Android manifest permissions without installing or executing the APK.
- **Adaptive learning hub:** quiz and report outcomes update topic confidence and recommendations. Learning progress is stored in browser local storage.

## Run locally

Start the backend in one terminal:

```powershell
cd backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

Start the frontend in another terminal:

```powershell
cd frontend
npm ci
npm run dev
```

The Vite development server proxies `/api` requests to the local backend. In Vercel deployments, the root `vercel.json` routes `/api/*` to the FastAPI service and all other paths to the Vite frontend.

## Vercel services

The `backend` service handles public `/api/*` requests. The `frontend` service handles `/*`. The backend's `/health` route is not publicly routed. There are no service bindings: browser code calls the public same-origin `/api` path, rather than making a server-side service-to-service request.

## Safety and upload limits

URL checks are static and never follow redirects or contact the submitted host. APK code is not executed. The analyzer accepts APKs up to 50 MB locally; Vercel Functions default to a 4.5 MB request-body limit, with a 20 MiB beta option under specific plan and project settings. Vercel will reject uploads larger than the active limit before they reach the analyzer. Supporting 50 MB uploads later requires changing the upload flow or hosting the analyzer elsewhere.
