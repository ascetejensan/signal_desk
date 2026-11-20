"""VirusTotal v3 reputation and opt-in scanning.

No file is submitted on selection or hash lookup. Uploads are explicit, limited,
authenticated by the application and sent only to the VirusTotal API. VT public
file submissions can be shared with security partners. Never upload secrets.
"""
import base64
import binascii
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
import re
from urllib.parse import quote, urlencode, urlsplit, urlunsplit
import urllib.error
import urllib.request
import uuid

BASE = "https://www.virustotal.com/api/v3"
MAX_FILE_BYTES = 2 * 1024 * 1024
STATS = ("malicious", "suspicious", "harmless", "undetected", "timeout", "failure", "type-unsupported", "confirmed-timeout")


class VTError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def _token():
    key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not key:
        raise VTError("VirusTotal is not configured on the server. Set VIRUSTOTAL_API_KEY.", 503)
    return key


def _api(method, path, body=None, content_type=None):
    headers = {"x-apikey": _token(), "Accept": "application/json"}
    if content_type:
        headers["Content-Type"] = content_type
    req = urllib.request.Request(BASE + path, headers=headers, data=body, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            raw = response.read(512 * 1024)
        return json.loads(raw)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        if exc.code == 429:
            raise VTError("VirusTotal API rate limit reached. Wait before retrying; free API quotas are limited.", 429) from None
        if exc.code in (401, 403):
            raise VTError("VirusTotal rejected the API key or this operation is not allowed by the current API plan.", 503) from None
        if exc.code == 413:
            raise VTError("VirusTotal rejected the upload size. Select a smaller file.", 413) from None
        raise VTError("VirusTotal returned HTTP " + str(exc.code) + ". Try again or check provider availability.", 503) from None
    except (urllib.error.URLError, TimeoutError):
        raise VTError("Unable to reach VirusTotal. Check the hosting connection and retry.", 503) from None
    except (ValueError, KeyError, TypeError):
        raise VTError("VirusTotal returned an unreadable response.", 502) from None


def _hash(raw):
    value = str(raw or "").strip().lower()
    if not re.fullmatch(r"(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})", value):
        raise VTError("Enter an MD5, SHA-1 or SHA-256 file hash.")
    return value


def _url(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 2048:
        raise VTError("Enter a public website URL of up to 2,048 characters.")
    value = value.strip()
    if re.search(r"[\x00-\x20\x7f<>\\]", value):
        raise VTError("The URL contains invalid characters.")
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        if parsed.scheme not in ("http", "https") or not host or parsed.username or parsed.password:
            raise VTError("Enter a public HTTP or HTTPS website URL without embedded credentials.")
        if parsed.port and not 1 <= parsed.port <= 65535:
            raise VTError("Invalid URL port.")
        host = host.lower().rstrip(".")
        if host in ("localhost", "localhost.localdomain") or host.endswith((".localhost", ".local", ".internal", ".test")) or "." not in host:
            raise VTError("Private, local and test URLs cannot be submitted to VirusTotal.")
        try:
            address = ipaddress.ip_address(host)
            if not address.is_global:
                raise VTError("Private or reserved IP addresses cannot be submitted.")
        except ValueError:
            pass
        # URL fragments are local browser references; do not send them to VT.
        clean = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
    except VTError:
        raise
    except (ValueError, TypeError):
        raise VTError("Enter a valid public HTTP or HTTPS URL.") from None
    return clean


def _report(kind, identifier, doc):
    attributes = (doc.get("data") or {}).get("attributes") or {}
    if not isinstance(attributes, dict):
        raise VTError("VirusTotal returned an incomplete report.", 502)
    found = attributes.get("last_analysis_stats")
    stats = {key: max(0, int(found.get(key, 0) or 0)) for key in STATS} if isinstance(found, dict) else None
    stamp = attributes.get("last_analysis_date")
    try:
        stamp = datetime.fromtimestamp(int(stamp), timezone.utc).isoformat() if stamp is not None else None
    except (ValueError, TypeError, OverflowError):
        stamp = None
    link = "https://www.virustotal.com/gui/" + kind + "/" + quote(identifier, safe="") + "/detection"
    return {
        "status": "found", "kind": kind, "source": "VirusTotal",
        "identifier": identifier, "stats": stats, "analysisTime": stamp,
        "reportUrl": link,
        "note": "Third-party reputation only. No detection does not guarantee safety; reports may be stale."
    }


def hash_report(body):
    value = _hash(body.get("hash"))
    doc = _api("GET", "/files/" + value)
    if doc is None:
        return {
            "status": "not_found", "kind": "file", "identifier": value,
            "message": "No existing VirusTotal report for this file hash. It has NOT been scanned by this lookup.",
            "source": "VirusTotal"
        }
    return _report("file", str((doc.get("data") or {}).get("attributes", {}).get("sha256") or value), doc)


def url_report(body):
    url = _url(body.get("url"))
    url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")
    doc = _api("GET", "/urls/" + quote(url_id, safe=""))
    if doc is None:
        return {
            "status": "not_found", "kind": "url", "url": url,
            "message": "No existing VirusTotal URL report. The website was NOT visited by CTI Sentinel.",
            "source": "VirusTotal"
        }
    # Prefer the canonical provider ID if available for the web report link.
    report_id = str((doc.get("data") or {}).get("id") or url_id)
    return {**_report("url", report_id, doc), "url": url}


def submit_file(body):
    if body.get("consent") is not True:
        raise VTError("Explicit consent is required to upload file contents to VirusTotal.")
    filename = body.get("filename")
    encoded = body.get("data")
    if not isinstance(filename, str) or not 1 <= len(filename) <= 120:
        raise VTError("Choose a file with a valid filename.")
    if not isinstance(encoded, str) or len(encoded) > (MAX_FILE_BYTES * 4 // 3 + 8):
        raise VTError("Upload a file no larger than 2 MB.", 413)
    try:
        binary = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        raise VTError("The uploaded file encoding is invalid.") from None
    if not binary or len(binary) > MAX_FILE_BYTES:
        raise VTError("Upload a non-empty file no larger than 2 MB.", 413)
    sha = hashlib.sha256(binary).hexdigest()
    if body.get("sha256") and _hash(body["sha256"]) != sha:
        raise VTError("The selected file changed. Please select it again before uploading.")
    name = re.sub(r"[^A-Za-z0-9_.-]", "_", filename.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]).strip("._")[:95] or "sample.bin"
    boundary = "CTISentinel" + uuid.uuid4().hex
    header = (
        "--" + boundary + "\r\n"
        'Content-Disposition: form-data; name="file"; filename="' + name + '"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode("ascii")
    payload = header + binary + ("\r\n--" + boundary + "--\r\n").encode("ascii")
    doc = _api("POST", "/files", payload, "multipart/form-data; boundary=" + boundary)
    aid = str((doc or {}).get("data", {}).get("id", ""))
    if not aid:
        raise VTError("VirusTotal accepted the request but did not return an analysis ID.", 502)
    return {
        "status": "queued", "kind": "file", "analysisId": aid, "sha256": sha,
        "source": "VirusTotal", "message": "File uploaded to VirusTotal. Analysis may still be pending.",
        "note": "File contents were sent to VirusTotal, where ordinary submissions can be shared with security partners."
    }


def submit_url(body):
    if body.get("consent") is not True:
        raise VTError("Explicit consent is required to submit this website URL to VirusTotal.")
    url = _url(body.get("url"))
    data = urlencode({"url": url}).encode("utf-8")
    doc = _api("POST", "/urls", data, "application/x-www-form-urlencoded")
    aid = str((doc or {}).get("data", {}).get("id", ""))
    if not aid:
        raise VTError("VirusTotal did not return a URL analysis ID.", 502)
    return {
        "status": "queued", "kind": "url", "analysisId": aid, "url": url,
        "source": "VirusTotal", "message": "URL submitted to VirusTotal. Analysis may still be pending.",
        "note": "The URL was shared with VirusTotal. CTI Sentinel did not visit it."
    }


def analysis(body):
    aid = str(body.get("analysisId") or "")
    if not re.fullmatch(r"[A-Za-z0-9_=-]{8,256}", aid):
        raise VTError("Invalid VirusTotal analysis ID.")
    doc = _api("GET", "/analyses/" + quote(aid, safe=""))
    if doc is None:
        return {"status": "not_found", "kind": "analysis", "message": "Analysis not found or no longer available."}
    attrs = (doc.get("data") or {}).get("attributes") or {}
    stage = attrs.get("status")
    if stage != "completed":
        return {"status": "queued", "kind": "analysis", "analysisId": aid,
                "message": "Analysis is still pending. Use Refresh analysis later."}
    raw = attrs.get("stats")
    stats = {key: max(0, int(raw.get(key, 0) or 0)) for key in STATS} if isinstance(raw, dict) else None
    if stats is None:
        return {"status": "completed", "kind": "analysis", "analysisId": aid,
                "stats": None, "message": "Analysis finished but no engine counts were returned."}
    return {"status": "completed", "kind": "analysis", "analysisId": aid,
            "stats": stats, "note": "Analysis counts are not a guarantee of safety.",
            "message": "VirusTotal analysis completed."}


def handle(action, body):
    if not isinstance(body, dict):
        raise VTError("JSON object required.")
    routes = {
        "hash": hash_report,
        "url": url_report,
        "file": submit_file,
        "url-submit": submit_url,
        "analysis": analysis,
    }
    if action not in routes:
        raise VTError("Unknown VirusTotal action.", 404)
    return routes[action](body)
