#!/usr/bin/env python3
"""I assemble my authorized CTI Sentinel website from a pinned upstream revision."""
from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = "https://github.com/SOLANKYYY/signal-desk.git"
PIN = "cc6189fb450eba758a57c7ebe9a8102327b7de12"
IDENTITY = (
    ("Solanki Om Narendra", "Ishan Mahansaria"),
    ("24BTRCL190", "24BTRCL085"),
    ("5AIMLB", "AIML B"),
    ("Signal Desk", "CTI Sentinel"),
)
TEXT_EXT = {".py", ".md", ".txt", ".html", ".css", ".js", ".json", ".yml", ".yaml", ".toml", ".ps1", ".cjs", ".example"}
PROTECTED = {"README.md", "SOURCE_ATTRIBUTION.md", "HOSTING_SETUP.md",
             "scripts/assemble_cloud.py", ".github/workflows/assemble-cloud.yml"}
DOCKER_REPOS = {
    11: "lab11-mongodb-sharding",
    12: "experiment12-mongodb-security",
    13: "lab13-mongodb-replica-set",
    14: "lab14-mongodb-labs",
    15: "lab15-mongodb-multitenant",
    16: "lab16-polyglot-query-service",
    17: "lab17-rag-vector-search",
    18: "lab18-threat-intelligence",
}


def customize(path: Path, contents: bytes) -> bytes:
    if path.suffix.lower() not in TEXT_EXT:
        return contents
    try:
        value = contents.decode("utf-8")
    except UnicodeError:
        return contents
    if path.as_posix() == "docs/FINAL_ASSESSMENT.md":
        # Keep the original experimental measurements attributed to their original owner.
        return (
            "> UPSTREAM REFERENCE ONLY: This is the original author's assessment. "
            "I have not claimed these measurements as mine. See SOURCE_ATTRIBUTION.md.\n\n"
            + value
        ).encode("utf-8")
    for old, new in IDENTITY:
        value = value.replace(old, new)
    if path.as_posix() == "backend/coursework.py":
        match = r"REPOS=\{n:\('mongodb-exercise13' if n==13 else 'nosql-exercise'\+str\(n\)\) for n,\*_ in TOPICS\}"
        replacement = "REPOS=" + repr(DOCKER_REPOS)
        value, count = re.subn(match, lambda _: replacement, value)
        if count != 1:
            raise RuntimeError("The upstream coursework Docker mapping changed; I stopped instead of guessing.")
        value = value.replace("'https://hub.docker.com/r/solankyyy/'+REPOS[n]",
                              "'https://hub.docker.com/r/ishanmahansaria/'+REPOS[n]")
    elif path.as_posix() == "tests/test_coursework.py":
        value = value.replace("'/mongodb-exercise13'", "'/lab13-mongodb-replica-set'")
    elif path.as_posix() == "frontend/intel.js":
        value = value.replace("Ask Signal Desk", "Ask CTI Sentinel")
    elif path.as_posix() == "docs/VERCEL_DEPLOYMENT.md":
        value = (
            "> For my own hosted application I follow HOSTING_SETUP.md at the repository root. "
            "This upstream document is supplementary and may contain the original author's paths.\n\n"
            + value
        )
    return value.encode("utf-8")


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="cti-upstream-") as temp:
        upstream = Path(temp) / "upstream"
        subprocess.run(["git", "clone", "--quiet", "--depth", "1", UPSTREAM, str(upstream)], check=True)
        subprocess.run(["git", "fetch", "--quiet", "--depth", "1", "origin", PIN], cwd=upstream, check=True)
        subprocess.run(["git", "checkout", "--quiet", PIN], cwd=upstream, check=True)
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=upstream, text=True).strip()
        if commit != PIN:
            raise RuntimeError("Upstream commit verification failed.")

        copied = 0
        for source in upstream.rglob("*"):
            if not source.is_file():
                continue
            relative = source.relative_to(upstream)
            if ".git" in relative.parts or any(part in {".venv", "__pycache__", "node_modules"} for part in relative.parts):
                continue
            if relative.name == ".env" or relative.suffix in {".pem", ".key", ".p12", ".pfx"}:
                continue
            if relative.as_posix() in PROTECTED:
                continue
            destination = ROOT / relative
            # This importer bootstraps missing files only; never replace the
            # maintained hosted app, its safety fixes or tested VirusTotal UI.
            if destination.exists():
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            data = source.read_bytes()
            destination.write_bytes(customize(relative, data))
            copied += 1

    docs = ROOT / "MY_DOCKER_HUB_LINKS.md"
    docs.write_text(
        "# My supplied Docker Hub links\n\n"
        "I list only the nine images I gave for my own exercises.\n\n"
        "| Experiment | My Docker Hub page |\n|---|---|\n"
        "| 09 | https://hub.docker.com/r/ishanmahansaria/lab9-mongo-tools |\n"
        + "".join(f"| {n:02d} | https://hub.docker.com/r/ishanmahansaria/{name} |\n"
                  for n, name in DOCKER_REPOS.items()),
        encoding="utf-8",
    )
    print(f"I assembled {copied} upstream files from verified commit {PIN}.")
    print("I did not insert Atlas connection strings, API keys or login passwords.")
    print("I have not deployed or tested the hosted website yet.")


if __name__ == "__main__":
    main()
