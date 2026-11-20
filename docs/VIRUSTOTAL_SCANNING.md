# VirusTotal reputation and scanning in CTI Sentinel

I use the **File & message checks** tab in the full, authenticated CTI Sentinel workspace. This feature uses the official VirusTotal v3 API with the server-only `VIRUSTOTAL_API_KEY`. It does not need Gemini and does not change the AI chatbot configuration.

## My file workflow

1. I choose a file. CTI Sentinel calculates SHA-256 and recognizes basic file signatures **in the browser** (no file contents are uploaded or executed).
2. I click **Look up hash with VirusTotal**. Only the hash is sent to `GET /api/v3/files/{hash}`.
3. If VirusTotal has a report, I see the last analysis date, detection counts for **malicious, suspicious, harmless, and undetected**, and a link to VirusTotal's full report.
4. **Hash not found** means no matching existing VirusTotal report, *not* that the file is safe or infected.
5. For a file that I have permission to share, I explicitly check the consent box and click **Upload selected file to VirusTotal**. This uploads the bytes using VirusTotal's `POST /api/v3/files` API. The hosted demonstration accepts files no larger than **2 MB** because Vercel has request-body limits.
6. I use **Refresh submitted file analysis** to check `GET /api/v3/analyses/{id}`. If analysis is still queued, the UI says so. Once complete it shows the engine counts and links to the file's report.

**Privacy and ethics:** Standard/public VirusTotal file uploads may be shared with third-party security partners. **Never upload confidential documents, research papers, credentials, student records, medical information, or unpublished material.** For those, I only use the local SHA-256 computation and optional hash-only reputation lookup. A hash-only lookup does not reveal the file contents, but it does reveal the hash to VirusTotal.

## My website URL workflow

1. I paste a **public** HTTP or HTTPS website URL.
2. **Look up website reputation** queries an existing VT URL report without visiting the submitted site. Unknown URLs do not get a clean verdict.
3. If I explicitly consent, **Submit URL to VirusTotal** requests a new analysis via `POST /api/v3/urls`. VirusTotal receives the submitted URL. CTI Sentinel still does not visit the URL itself.
4. I use **Refresh submitted URL analysis** for the status and engine-count results.

Never paste internal URLs, signed links, private tokens or sensitive query parameters into URL scanning. The application rejects localhost and common internal/reserved destinations.

## What the counts mean

* **Malicious:** number of provider engines classifying the sample/URL as malicious.
* **Suspicious:** engines suggesting risk.
* **Harmless:** engines that did not classify it as malicious.
* **Undetected:** engines with no detection.
* **Timed out / unsupported / failed:** not a successful check.

These counts are third-party classifications. A zero-malicious result is **not** proof of safety. A low count can also reflect false positives. Reports can be stale; use the last-analysis date and the full report to interpret them.

## Expected API behavior

| Situation | What my interface shows |
|---|---|
| Valid hash with existing VT report | Date, four engine counts, provider report link |
| New private or unknown file hash | No existing report; no claim of safety |
| Consented small file upload | Analysis queued and status refresh control |
| Analysis completed | Engine counts (when provider supplies them) |
| Known website URL | Existing reputation and analysis date |
| Consent to scan a public URL | Queued URL analysis and status refresh |
| No server API key | Clearly marked configuration error |
| Free-tier API rate limit (HTTP 429) | Wait before retrying; no false verdict |
| Invalid/restricted API key | Explicit provider access error |
| File larger than 2 MB for remote scan | Local hash works, hosted upload disabled |

## Implementation and test files

* `backend/virustotal.py` implements the v3 API client and report normalization.
* `frontend/vt_ui.js` provides file and URL reputation reports, opt-in scan controls and clear engine-count summaries.
* `backend/web.py` handles authenticated `POST /api/vt/*` requests on Vercel.
* `backend/server.py` handles the same actions on the Windows/local Python server.
* `tests/test_virustotal.py` exercises report responses, missing hashes, consent requirements, size limits, rate limits, URL validation and protected API routes. The tests use mocked VT API responses and never upload real files.

The API key remains a secret in Vercel project environment variables; never put it in source code, URLs, client JavaScript, email or a report appendix.

Official VirusTotal API references:

* File reports: https://docs.virustotal.com/reference/file-info
* File upload: https://docs.virustotal.com/reference/files-scan
* Analysis status: https://docs.virustotal.com/reference/analysis
* URL report: https://docs.virustotal.com/reference/url-info
* URL scan: https://docs.virustotal.com/reference/scan-url
