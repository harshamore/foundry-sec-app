"""Repo ingestion.

Fetches a public GitHub repository as a tarball through the GitHub API (no git
binary required, which matters on Streamlit Cloud) and unpacks the source files
into a temp directory. An optional token raises the rate limit and enables
private repos. Hard caps on file count and bytes keep a giant monorepo from
blowing the budget — the Coverage-Guide later reports what fraction was swept.
"""

from __future__ import annotations

import io
import os
import re
import tarfile
import tempfile
from dataclasses import dataclass
from typing import List, Optional, Tuple

import requests

SOURCE_EXTS = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go",
               ".rb", ".php", ".c", ".cpp", ".cs", ".rs"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv",
             "dist", "build", "vendor", ".next", "target"}

MAX_FILES = 60
MAX_BYTES_PER_FILE = 200_000
GITHUB_URL_RE = re.compile(
    r"github\.com[/:]+([\w.\-]+)/([\w.\-]+?)(?:\.git)?/?$", re.I)


@dataclass
class SourceFile:
    path: str       # repo-relative path
    code: str


def parse_repo_url(url: str) -> Tuple[str, str]:
    m = GITHUB_URL_RE.search(url.strip())
    if not m:
        raise ValueError(
            "Could not parse a GitHub owner/repo from that URL. "
            "Expected something like https://github.com/owner/repo")
    return m.group(1), m.group(2)


def _download_tarball(owner: str, repo: str, token: Optional[str]) -> bytes:
    """Get the repo tarball. Prefers the authenticated REST API (supports the
    default branch + private repos); falls back to codeload (not REST-rate-
    limited) on common branches when unauthenticated and throttled."""
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "foundry-sec-app"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    api = f"https://api.github.com/repos/{owner}/{repo}/tarball"
    r = requests.get(api, headers=headers, timeout=60, allow_redirects=True)
    if r.status_code == 200:
        return r.content
    if r.status_code == 404:
        raise ValueError(f"Repo {owner}/{repo} not found (or private without a token).")
    if r.status_code == 403 and not token:
        # REST API throttled — try codeload directly (default branches).
        for branch in ("main", "master"):
            cl = requests.get(
                f"https://codeload.github.com/{owner}/{repo}/tar.gz/refs/heads/{branch}",
                timeout=60)
            if cl.status_code == 200:
                return cl.content
        raise ValueError(
            "GitHub REST rate limit hit and codeload fallback failed "
            "(non-standard default branch?). Add a GitHub token in the sidebar.")
    if r.status_code == 403:
        raise ValueError("GitHub rate limit hit even with a token. Try again shortly.")
    r.raise_for_status()
    return r.content


def fetch_repo(url: str, token: Optional[str] = None
               ) -> Tuple[List[SourceFile], dict]:
    """Return (source_files, meta). Raises on hard failure."""
    owner, repo = parse_repo_url(url)
    content = _download_tarball(owner, repo, token)

    files: List[SourceFile] = []
    truncated = False
    total_source_in_repo = 0
    with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            # strip the leading "owner-repo-sha/" component
            rel = member.name.split("/", 1)[1] if "/" in member.name else member.name
            parts = rel.split("/")
            if any(p in SKIP_DIRS for p in parts):
                continue
            if os.path.splitext(rel)[1].lower() not in SOURCE_EXTS:
                continue
            total_source_in_repo += 1
            if len(files) >= MAX_FILES:
                truncated = True
                continue
            f = tf.extractfile(member)
            if f is None:
                continue
            raw = f.read(MAX_BYTES_PER_FILE + 1)
            if len(raw) > MAX_BYTES_PER_FILE:
                continue  # skip very large generated files
            try:
                code = raw.decode("utf-8", errors="replace")
            except Exception:
                continue
            if code.strip():
                files.append(SourceFile(path=rel, code=code))

    meta = {
        "owner": owner, "repo": repo,
        "source_files_total": total_source_in_repo,
        "source_files_indexed": len(files),
        "truncated": truncated,
        "cap": MAX_FILES,
    }
    return files, meta


def load_sample(path: str) -> List[SourceFile]:
    code = open(path, "r", encoding="utf-8", errors="replace").read()
    return [SourceFile(path=os.path.basename(path), code=code)]
