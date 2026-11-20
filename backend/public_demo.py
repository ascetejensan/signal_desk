"""I expose a safe, read-only preview of my bundled public intelligence snapshot.

I never expose credentials, private analyst notes, conversation history or database writes.
I don't claim this snapshot is a real-time feed.
"""
from functools import lru_cache
from pathlib import Path
import gzip
import json

BASE = Path(__file__).resolve().parents[1]
SNAPSHOT = BASE / "data" / "public-threat-snapshot.json.gz"


@lru_cache(maxsize=1)
def snapshot():
    with gzip.open(SNAPSHOT, "rt", encoding="utf-8") as fh:
        data = json.load(fh)
    events = data.get("events", [])
    records = data.get("records", [])
    safe = []
    for event in events:
        if not isinstance(event, dict):
            continue
        safe.append({
            "title": str(event.get("title") or "Untitled report")[:200],
            "publisher": str(event.get("source") or event.get("feed") or "Public feed")[:120],
            "date": str(event.get("eventDate") or event.get("timestamp") or "")[:30],
            "reportedIndicators": int(event.get("indicatorCount") or 0),
            "reference": str(event.get("url") or "")[:350] if str(event.get("url") or "").startswith("https://") else ""
        })
    safe.sort(key=lambda x: x["date"], reverse=True)
    return {"events": safe, "totalObservations": len(records)}


def get(path, args):
    data = snapshot()
    if path == "summary":
        return {
            "title": "CTI Sentinel — public preview",
            "snapshotEvents": len(data["events"]),
            "snapshotObservations": data["totalObservations"],
            "provenance": "Bundled public-source snapshot from the authorized Signal Desk source",
            "freshness": "Static snapshot. These records are not current feed activity.",
            "scope": "Published indicator observations are not confirmed infections, attacks, or victims.",
            "readOnly": True
        }
    if path == "events":
        query = str(args.get("q") or "").strip().casefold()[:100]
        rows = [row for row in data["events"]
                if not query or query in (row["title"] + " " + row["publisher"]).casefold()]
        try:
            page = max(1, min(int(args.get("page", 1)), 1000))
        except (ValueError, TypeError):
            page = 1
        start = (page - 1) * 15
        return {"items": rows[start:start + 15], "total": len(rows), "page": page,
                "readOnly": True, "source": "Bundled public snapshot"}
    raise ValueError("Unknown public demo route")
