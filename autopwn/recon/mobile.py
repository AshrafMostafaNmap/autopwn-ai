"""Static, read-only Android APK inventory: components, permissions, embedded
URLs and hardcoded secrets (vaulted). Size-guarded against zip bombs.
"""
from __future__ import annotations

import re
import zipfile
from pathlib import Path

from .target_model import Surface

_MAX_FILE = 25 * 1024 * 1024        # skip any single entry larger than 25 MB
_MAX_TOTAL = 400 * 1024 * 1024      # stop after scanning 400 MB uncompressed
_SCAN_EXT_SKIP = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".ttf", ".otf", ".mp3", ".mp4", ".ogg"}

_PERM_RE = re.compile(r"android\.permission\.[A-Z_]+")
_PKG_RE = re.compile(r"\b([a-z][a-z0-9_]*(?:\.[a-z0-9_]+){2,})\b")
_URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,}")
_SECRET_RE = [
    ("google-api", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("aws-akid", re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}")),
    ("firebase", re.compile(r"[a-z0-9-]+\.firebaseio\.com")),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
    ("generic", re.compile(r"(?i)(?:api[_-]?key|secret|token|password)[\"'\s:=]{1,4}[A-Za-z0-9_\-]{12,}")),
]


def apk_inventory(path: str, *, vault=None) -> tuple[Surface, dict]:
    p = Path(path)
    host = p.name
    surface = Surface(host=host, domain="mobile")
    raw: dict = {"file": str(p)}

    if not p.is_file():
        surface.notes.append("APK not found")
        raw["error"] = "file not found"
        return surface, raw
    if not zipfile.is_zipfile(p):
        surface.notes.append("not a valid APK/zip")
        raw["error"] = "not a zip"
        return surface, raw

    dex, libs, assets, perms, urls = 0, set(), 0, set(), set()
    secrets_found: list[str] = []
    flags = {"cleartext": False, "debuggable": False, "exported": False}
    scanned = 0

    with zipfile.ZipFile(p) as zf:
        names = zf.namelist()
        raw["entry_count"] = len(names)
        has_manifest = "AndroidManifest.xml" in names
        for name in names:
            low = name.lower()
            if low.endswith(".dex"):
                dex += 1
            elif low.startswith("lib/") and low.endswith(".so"):
                libs.add(name.split("/")[-1])
            elif low.startswith("assets/"):
                assets += 1

        # scan text-ish content for perms / urls / secrets, under guards
        for info in zf.infolist():
            if info.file_size > _MAX_FILE or scanned > _MAX_TOTAL:
                continue
            ext = Path(info.filename).suffix.lower()
            if ext in _SCAN_EXT_SKIP:
                continue
            is_manifest = info.filename == "AndroidManifest.xml"
            is_text = is_manifest or info.filename.endswith(".dex") or ext in ("", ".xml", ".json", ".txt", ".properties", ".js")
            if not is_text:
                continue
            try:
                data = zf.read(info.filename)
            except Exception:
                continue
            scanned += len(data)
            text = data.decode("latin-1", "replace")
            if is_manifest:
                # binary XML: UTF-16 strings; decode both ways and union
                utf16 = data.decode("utf-16-le", "replace")
                for t in (text, utf16):
                    perms.update(_PERM_RE.findall(t))
                raw["package_candidates"] = _PKG_RE.findall(utf16)[:5]
                blob = (text + utf16).lower()
                # heuristic manifest flags (presence of the attribute string)
                if "usescleartexttraffic" in blob:
                    flags["cleartext"] = True
                if "debuggable" in blob:
                    flags["debuggable"] = True
                if "exported" in blob:
                    flags["exported"] = True
            for u in _URL_RE.findall(text):
                urls.add(u[:200])
            for kind, rx in _SECRET_RE:
                for hit in rx.findall(text):
                    secret = hit if isinstance(hit, str) else hit[0]
                    if vault is not None:
                        vault.tokenize(secret, kind="apk-secret", hint=f"{kind}:{info.filename}")
                    secrets_found.append(kind)

    surface.tech = sorted(libs)[:20]
    surface.endpoints = sorted(urls)[:50]
    surface.notes.append(f"dex={dex} libs={len(libs)} assets={assets} manifest={'yes' if has_manifest else 'no'}")
    if perms:
        surface.notes.append(f"permissions ({len(perms)}): " + ", ".join(sorted(perms)[:15]))
    if secrets_found:
        from collections import Counter
        tally = ", ".join(f"{k}×{v}" for k, v in Counter(secrets_found).items())
        surface.notes.append(f"hardcoded secrets (vaulted): {tally}")
    raw.update({"dex": dex, "libs": sorted(libs), "assets": assets,
                "permissions": sorted(perms), "urls": sorted(urls)[:50],
                "secret_kinds": secrets_found, "flags": flags})
    return surface, raw
