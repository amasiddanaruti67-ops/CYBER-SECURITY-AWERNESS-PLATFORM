# Sentinel Cyber Awareness Platform

An integrated training and static-analysis web app for phishing awareness, URL and email-header forensics, Android APK permission review, and adaptive micro-learning.

## Features

- **Phishing lab:** interactive, simulated scenarios with a short learning drill. It does not send emails, collect credentials, or open message links.
- **URL and email forensics:** static URL heuristics and local analysis of pasted email headers. No DNS, WHOIS, reputation, or redirect lookups are performed.
- **APK analyzer:** reviews Android manifest permissions without installing or executing the APK. Uploads are processed by the configured backend and are not saved as files.
- **Adaptive learning hub:** quiz and report outcomes update topic confidence and recommendations. Learning progress is stored in the browser's local storage.

## Run locally

Use two terminals.

Start the backend:

```powershell
cd backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

Start the frontend:

```powershell
cd frontend
npm ci
npm run dev
```

Open the Vite URL shown in the terminal (normally `http://localhost:5173`). The frontend uses the local API at `http://localhost:8000`; when it is unavailable, the scenario catalog and sample APK profiles remain available offline.

## Safety notes

All analysis is static and heuristic; results are indicators, not proof that a URL or APK is safe or malicious. The URL analyzer never follows redirects or contacts the submitted host. Do not upload APKs containing sensitive or proprietary information to a backend you do not control.
