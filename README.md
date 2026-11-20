# CTI Sentinel — AI Threat Intelligence & MongoDB Research Workspace

**Student:** Ishan Mahansaria  
**USN:** 24BTRCL085  
**Class:** AIML B  
**Faculty:** Sujeet Jagtap  
**Course:** 23CSE528 — NoSQL Database using MongoDB

CTI Sentinel is my hosted academic threat-intelligence and MongoDB application, adapted from the [original Signal Desk project](https://github.com/SOLANKYYY/signal-desk) with appropriate source attribution.

## Open the application

| Destination | Link | Notes |
|---|---|---|
| **Live CTI Sentinel** | **[Open Full Website](https://cti-sentinel-ishan.vercel.app/)** | Hosted Flask interface; full workspace requires an application login |
| **Public demo** | **[Open No-Login Demo](https://cti-sentinel-ishan.vercel.app/demo)** | Read-only historical public-intelligence snapshot, plus local hash demonstration |
| **VirusTotal scanner** | [File and URL reputation](https://cti-sentinel-ishan.vercel.app/#scan) | Authenticated full workspace; API access is subject to VirusTotal quotas |
| **Coursework repository** | [NoSQL laboratory submission](https://github.com/ascetejensan/CTI-Sentinel-AI-Threat-Intelligence) | **Private**; the owner must grant GitHub access to reviewers |
| **Lab submission source pointer** | [Mini-project SOURCE.md](https://github.com/ascetejensan/CTI-Sentinel-AI-Threat-Intelligence/blob/main/mini-project/SOURCE.md) | Explains why this is the maintained app repository; private link |

**This repository contains the maintained mini-project source.** My separate [`CTI-Sentinel-AI-Threat-Intelligence`](https://github.com/ascetejensan/CTI-Sentinel-AI-Threat-Intelligence) repository organizes the 18 coursework experiments, Docker Hub references, report drafts and an earlier local-source snapshot.

## Main features

| Workspace area | Function |
|---|---|
| Workspace Home | Research overview and database-backed counts |
| AI Threat Assistant | Optional provider-backed answers and context, with MongoDB storage; requires working provider quota/billing |
| Threat Explorer | Explore published indicator observations and reported events |
| Shared Indicators | Review common observables in the collected public feeds |
| File & Message Checks | Browser-side file SHA-256, VirusTotal reputation, explicit file and website submissions, clear detection counts |
| Investigation Notebook | Save and review case notes in MongoDB |
| Database Experiments | Academic MongoDB laboratory evidence and experiment interface |
| Compare Databases | Review database models, workloads and trade-offs |
| Evidence Library | Search indexed report evidence where available |
| Sources & Coverage | Track published feed sources and coverage metadata |
| Export Intelligence | Export documented public-feed observations |

**Reputation is not a safety verdict:** VirusTotal engine counts are third-party assessments, and a missing hash does not prove that a file is clean. The UI requires explicit consent before sending file contents or public URLs to the provider. On Vercel, optional file submission is limited to **2 MB**; local SHA-256 calculation supports files up to 20 MB.

## VirusTotal implementation and usage

The current scanner supports four distinct workflows:

1. **Local file check:** Select a file and compute SHA-256 in your browser. This does not execute, upload or scan the file.
2. **Hash reputation:** Look up MD5, SHA-1 or SHA-256 against the existing VirusTotal database; display reported malicious, suspicious, harmless and undetected classifications and the provider report link if present.
3. **Consented file scan:** Submit a non-confidential file to VirusTotal's v3 API, then refresh the analysis ID to view counts after processing.
4. **Website reputation and URL analysis:** Check existing reports for public URLs, or explicitly consent to request a new URL analysis.

Uploaded files may be shared with security partners. Never upload confidential coursework, personal files, student records, credentials or unpublished research. Follow [**the full VirusTotal scanning guide**](docs/VIRUSTOTAL_SCANNING.md) for restrictions, API errors and test coverage.

## Project architecture

| Layer | Technology / role |
|---|---|
| Frontend | Vanilla HTML, CSS and JavaScript, including `frontend/intel.js` and `frontend/vt_ui.js` |
| Backend | Python 3.12 and Flask; `backend/web.py` serves Vercel |
| Data persistence | MongoDB Atlas using `MONGODB_URI` |
| VirusTotal | v3 API called **server-side** using `VIRUSTOTAL_API_KEY` |
| Optional AI | Gemini, OpenAI or local Ollama; hosted access depends on configured provider, model and quota |
| Hosting | Vercel; the public demo is distinct from the password-protected workspace |
| Automated checks | GitHub Actions: Python tests, JavaScript syntax checks and project structure |

### Navigation for reviewers

- [Hosting and server environment](HOSTING_SETUP.md)
- [VirusTotal usage and privacy](docs/VIRUSTOTAL_SCANNING.md)
- [Source attribution](SOURCE_ATTRIBUTION.md)
- [Docker Hub experiment references](MY_DOCKER_HUB_LINKS.md)
- [Automated tests](https://github.com/ascetejensan/signal_desk/actions/workflows/verify-cti.yml)
- [Application implementation](backend/)
- [Frontend source](frontend/)
- [Tests](tests/)
- [Coursework submission index](https://github.com/ascetejensan/CTI-Sentinel-AI-Threat-Intelligence/blob/main/README.md) (**private repository**)

## Cloud deployment

The website is hosted at **https://cti-sentinel-ishan.vercel.app/**, with a verified publicly accessible demo at [`/demo`](https://cti-sentinel-ishan.vercel.app/demo). To deploy a personal copy, read [HOSTING_SETUP.md](HOSTING_SETUP.md), configure the Vercel project and set required server-side secrets privately.

Typical server environment keys include:

| Key | Purpose |
|---|---|
| `APP_USERNAME`, `APP_PASSWORD` | Application login; never commit actual passwords |
| `MONGODB_URI`, `MONGODB_DB` | MongoDB Atlas connection and database name |
| `VIRUSTOTAL_API_KEY` | Server-side file and URL reputation/analysis |
| `LLM_BACKEND`, `GEMINI_API_KEY`, `GEMINI_MODEL` | Optional Gemini chat configuration |
| `EMBEDDING_MODEL`, `EMBEDDING_DIMENSIONS`, `CHAT_RETRIEVAL` | Optional evidence retrieval settings |
| `CRON_SECRET` | Private scheduled-job authorization |

The professor does **not** need to install Git, Python, Docker, MongoDB or Ollama just to open the hosted website. Access to the complete workspace requires a login shared privately by the owner; the public demo is read-only.

**Verification boundary:** The Vercel production deployment and GitHub automated tests have succeeded. The VirusTotal provider tests use mocked responses; a live end-to-end upload has not been independently confirmed. AI answers are conditional on provider access and available API credits. Google Gemini has previously returned HTTP 402 (payment/credit required) on this deployment; that provider issue is outside the README and VirusTotal changes.

## Repository and lab submission separation

I keep the **maintained mini-project source and releases** here and the **18 NoSQL/MongoDB laboratory chapters and reports** in the separate course submission repository. The copies under its `mini-project/` folder are earlier local snapshots and need not match the latest hosted deployment.

Original implementation attribution: [SOLANKYYY/signal-desk](https://github.com/SOLANKYYY/signal-desk). See [SOURCE_ATTRIBUTION.md](SOURCE_ATTRIBUTION.md) for provenance and independent-evidence limits. I do not claim original authorship of reused code or reproduce prior experiment benchmarks as my own measurements.

---

**Maintained source:** https://github.com/ascetejensan/signal_desk  
**Coursework index (private):** https://github.com/ascetejensan/CTI-Sentinel-AI-Threat-Intelligence  
**Live website:** https://cti-sentinel-ishan.vercel.app/
