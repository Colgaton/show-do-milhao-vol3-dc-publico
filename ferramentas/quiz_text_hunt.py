#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
quiz_text_hunt.py -- recon tool for finding quiz questions/answers inside a
Windows game folder (the OCX/LDB era: VB6, Delphi, .NET, Access, SQLite...).

What it does (zero dependencies, Python 3.8+ stdlib only, READ-ONLY):
  1. Census of every file (extension, size).
  2. Fingerprints files by magic bytes (so renamed databases get found):
     Access Jet/ACE, SQLite, ZIP, RAR, 7z, CAB, SWF, PE .exe/.dll/.ocx, ...
  3. Extracts printable strings twice: 8-bit (CP1252, so accented Spanish/
     French/German text survives) and UTF-16LE (how VB6/Delphi store text).
  4. Scores every string for "looks like a quiz question / answer" and ranks
     files by question-likelihood.
  5. Flags connection-string/password hints (Jet OLEDB, Data Source=...).
  6. If a SQLite DB is found: copies it and dumps every table to CSV.
  7. If mdbtools (mdb-tables/mdb-export) is on PATH (Linux/WSL): dumps
     Access tables to CSV too.
  Existing CSV / string-dump files are NEVER overwritten: if a file already
  exists, the new one gets a _1, _2, _3, ... suffix instead.
  8. Writes a full report + per-file string dumps to an output folder.

Usage:
    python quiz_text_hunt.py "C:\\Games\\QuizGame"
    python quiz_text_hunt.py ./game --out ./hunt --top 15

Nothing in the target folder is ever modified.
"""

from __future__ import annotations

import argparse
import collections
import csv
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(errors="replace")

# ----------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------

MEDIA_EXT = {
    ".mp3", ".wav", ".ogg", ".wma", ".mid", ".midi", ".aif", ".aiff",
    ".avi", ".mpg", ".mpeg", ".mp4", ".wmv", ".mov", ".mkv",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".tif", ".tiff",
    ".psd", ".ttf", ".otf", ".fon", ".pcx", ".tga", ".webp",
}

MAGICS = [
    (b"Standard Jet DB", "Microsoft Access (Jet) database  <== LIKELY QUESTION BANK"),
    (b"Standard ACE DB", "Microsoft Access (ACE) database  <== LIKELY QUESTION BANK"),
    (b"SQLite format 3", "SQLite database  <== LIKELY QUESTION BANK"),
    (b"\x00\x01\x00\x00", "possible Access Jet database header"),
    (b"\xd0\xcf\x11\xe0", "OLE2 compound file (old .doc/.xls/.msi, ancient Access)"),
    (b"PK\x03\x04", "ZIP archive (may be .jar, or a renamed .zip/.pak)"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"MSCF", "Microsoft Cabinet (.cab)"),
    (b"GFX", "Flash .swf (newer)"),
    (b"CWS", "Flash .swf (zlib-compressed)"),
    (b"ZWS", "Flash .swf (LZMA)"),
    (b"FWS", "Flash .swf (uncompressed Flash movie)"),
    (b"\x1f\x8b", "gzip stream"),
    (b"RIFF", "RIFF container (.wav/.avi)"),
    (b"{\\rtf", "RTF document"),
    (b"MZ", "Windows PE executable / DLL / OCX"),
    (b"\x89PNG", "PNG image"),
    (b"<?xml", "XML document"),
    (b"{\"", "possible JSON"),
]

# Printable 8-bit run (includes CP1252 accents so Spanish/French/German text
# is not chopped at every accented character).
ASCII_RUN = rb"[\x20-\x7e\xa0-\xff]{%d,}"
# UTF-16LE run: printable char followed by a zero high byte.
UTF16_RUN = rb"(?:[\x20-\x7e\xa0-\xff]\x00){%d,}"

# Question-likelihood keywords (multi-language; extend as needed).
Q_WORDS = (
    "what", "which", "who ", "whose", "where", "when", "why", "how many",
    "how much", "how long", "how old",
    "qué", "que es", "cuál", "cuales", "cuáles", "quién", "quienes",
    "cómo", "cuándo", "dónde", "cuánt",
    "welche", "welcher", "was ist", "wer ist", "wie viele",
    "quale", "quali", "chi ", "dove", "quando",
    "quel", "quelle", "qui est", "combien",
    "qual", "quem", "onde", "quando",
)
OPT_RE = re.compile(r"^\s*[A-Fa-f][\.\)\:\-]\s")
NUM_RE = re.compile(r"^\s*\d{1,3}[\.\)\:\-]\s")

# Hints that reveal the database file name / password used by the game.
CONN_RE = re.compile(
    r"(oledb|\.mdb\b|\.accdb\b|\.sqlite\b|\.dbf\b|provider\s*=|data\s*source\s*=|"
    r"database\s*password|jet oledb|connectionstring)",
    re.I,
)


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

def read_head(path: str, n: int = 256) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(n)
    except OSError:
        return b""


def sniff(head: bytes) -> str | None:
    """Identify a file from its magic bytes (catches renamed files)."""
    if b"Standard Jet DB" in head[:32]:
        return "Microsoft Access (Jet) database  <== LIKELY QUESTION BANK"
    if b"Standard ACE DB" in head[:32]:
        return "Microsoft Access (ACE) database  <== LIKELY QUESTION BANK"
    for sig, desc in MAGICS:
        if head.startswith(sig) and desc.startswith("possible Access") and sig != head[:4]:
            continue
        if head.startswith(sig):
            return desc

    # Not a known binary signature: is it text?
    if len(head) >= 32:
        even = head[0::2]
        odd = head[1::2]
        if odd and odd.count(0) / len(odd) > 0.6 and even.count(0) / len(even) < 0.1:
            return "text encoded as UTF-16LE"
        printable = sum(1 for b in head if 9 <= b <= 13 or 32 <= b <= 255)
        if printable / len(head) > 0.90:
            return "plain / ASCII-CP1252 text"
    return None


def extract_strings(data: bytes, minlen: int) -> tuple[list[str], list[str]]:
    """Return (8-bit strings, UTF-16LE strings)."""
    a = re.compile(ASCII_RUN % minlen)
    w = re.compile(UTF16_RUN % minlen)

    def decode8(chunk: bytes) -> str:
        # SQLite/HTML/JSON hold UTF-8; fall back to CP1252 for legacy files.
        try:
            return chunk.decode("utf-8")
        except UnicodeDecodeError:
            return chunk.decode("cp1252", "replace")

    eight = [decode8(m.group()) for m in a.finditer(data)]
    wide = [m.group().decode("utf-16-le", "replace") for m in w.finditer(data)]
    return eight, wide


def quiz_score(line: str) -> int:
    s = 0
    if "?" in line or "¿" in line:
        s += 4
    low = line.lower()
    for w in Q_WORDS:
        if w in low:
            s += 2
            break
    if OPT_RE.match(line):
        s += 2
    if NUM_RE.match(line):
        s += 1
    return s


def flat_name(path: str, root: str) -> str:
    rel = os.path.relpath(path, root)
    return rel.replace("\\", "__").replace("/", "__").replace(":", "_")


def safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.\-]+", "_", name) or "table"


def unique_path(outdir: str, base: str, ext: str = ".csv") -> str:
    """Never overwrite: if base.ext exists, return base_1.ext, base_2.ext, ..."""
    cand = os.path.join(outdir, base + ext)
    n = 0
    while os.path.exists(cand):
        n += 1
        cand = os.path.join(outdir, "%s_%d%s" % (base, n, ext))
    return cand


# ----------------------------------------------------------------------------
# Database dumping
# ----------------------------------------------------------------------------

def dump_sqlite(path: str, outdir: str) -> list[tuple[str, str]]:
    """Copy the DB (so locks are never an issue), export every table to CSV."""
    made: list[tuple[str, str]] = []
    tmp = tempfile.mkdtemp(prefix="qz_hunt_")
    try:
        dst = os.path.join(tmp, "copy.sqlite")
        shutil.copy2(path, dst)
        con = sqlite3.connect(dst)
        cur = con.cursor()
        tables = [r[0] for r in cur.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('table','view')")]
        for t in tables:
            try:
                rows = cur.execute('SELECT * FROM "%s"' % t.replace('"', '""'))
                cols = [d[0] for d in rows.description]
                fn = unique_path(outdir, safe_name(t))
                with open(fn, "w", newline="", encoding="utf-8", errors="replace") as f:
                    w = csv.writer(f)
                    w.writerow(cols)
                    for r in rows:
                        w.writerow(r)
                made.append((t, fn))
            except sqlite3.Error as e:
                made.append((t, "ERROR: %s" % e))
        con.close()
    except (sqlite3.Error, OSError) as e:
        made.append(("<database>", "ERROR: %s" % e))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return made


def dump_access_mdbtools(path: str, outdir: str) -> list[tuple[str, str]] | None:
    """If mdbtools is installed (Linux/WSL), export Access tables to CSV."""
    if not shutil.which("mdb-tables"):
        return None
    made: list[tuple[str, str]] = []
    tmp = tempfile.mkdtemp(prefix="qz_hunt_")
    try:
        dst = os.path.join(tmp, "copy.mdb")
        shutil.copy2(path, dst)
        p = subprocess.run(["mdb-tables", "-1", dst], capture_output=True, text=True)
        tables = [t.strip() for t in p.stdout.splitlines() if t.strip()]
        for t in tables:
            fn = unique_path(outdir, safe_name(t))
            with open(fn, "w", encoding="utf-8", errors="replace") as f:
                subprocess.run(["mdb-export", dst, t], stdout=f,
                               stderr=subprocess.DEVNULL)
            made.append((t, fn))
    except Exception as e:  # noqa: BLE001 - best effort
        made.append(("<database>", "ERROR: %s" % e))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return made


# ----------------------------------------------------------------------------
# Main scan
# ----------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="Find quiz text in a game folder.")
    ap.add_argument("root", help="game folder to scan")
    ap.add_argument("--out", default="quiz_hunt_out", help="output folder")
    ap.add_argument("--min-len", type=int, default=5, help="min string length")
    ap.add_argument("--top", type=int, default=10, help="top lines per file")
    ap.add_argument("--max-mb", type=int, default=64, help="skip files larger than this (MB)")
    args = ap.parse_args()

    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        print("Not a folder: %s" % root)
        return 1

    outdir = os.path.abspath(args.out)
    strdir = os.path.join(outdir, "strings")
    os.makedirs(strdir, exist_ok=True)

    report_lines: list[str] = []

    def say(line: str = "") -> None:
        print(line)
        report_lines.append(line)

    say("=== Quiz text hunt ===")
    say("Root: %s" % root)

    census: dict[str, list[int]] = collections.defaultdict(lambda: [0, 0])
    records = []
    skipped_media = [0, 0]
    max_bytes = args.max_mb * 1024 * 1024

    for dirpath, dirnames, filenames in os.walk(root):
        for name in filenames:
            p = os.path.join(dirpath, name)
            try:
                size = os.path.getsize(p)
            except OSError:
                continue
            ext = os.path.splitext(name)[1].lower()
            if ext in MEDIA_EXT:
                skipped_media[0] += 1
                skipped_media[1] += size
                continue
            census[ext or "(none)"][0] += 1
            census[ext or "(none)"][1] += size
            head = read_head(p)
            kind = sniff(head)
            if ext == ".ldb":
                kind = ("Access lock file (.ldb) -- NOT quiz data; only records "
                        "which PC/user had the .mdb open")
            rec = {
                "path": p, "size": size, "ext": ext, "kind": kind,
                "strings8": [], "strings16": [], "hints": [],
                "error": None,
            }
            if size <= max_bytes:
                try:
                    with open(p, "rb") as f:
                        data = f.read()
                    rec["strings8"], rec["strings16"] = extract_strings(data, args.min_len)
                except OSError as e:
                    rec["error"] = str(e)
            else:
                rec["error"] = "skipped for strings: > %d MB" % args.max_mb
            records.append(rec)

    say("Scanned %d candidate files; skipped %d media files (%.1f MB)."
        % (len(records), skipped_media[0], skipped_media[1] / 1048576))

    # ---- census -------------------------------------------------------------
    say()
    say("--- Files by extension ---")
    for ext, (n, tot) in sorted(census.items(), key=lambda kv: -kv[1][1]):
        say("  %-8s %4d file(s)  %9.1f MB" % (ext, n, tot / 1048576))

    # ---- score every file ---------------------------------------------------
    scored = []
    for rec in records:
        all_lines = rec["strings8"] + rec["strings16"]
        scored_lines = sorted(
            ((quiz_score(s), s) for s in all_lines),
            key=lambda t: -t[0],
        )
        top = [(sc, s) for sc, s in scored_lines[:args.top] if sc > 0]
        maxscore = scored_lines[0][0] if scored_lines else 0
        if rec["ext"] == ".ldb":
            # Lock files contain only machine/user names -- show them all.
            top = [(0, s) for s in all_lines[:args.top]]
        for s in all_lines[:200000]:
            if CONN_RE.search(s) and len(s) < 400:
                rec["hints"].append(s)
                if len(rec["hints"]) >= 15:
                    break
        rec["top"] = top
        rec["maxscore"] = maxscore
        rec["n_strings"] = len(all_lines)
        boost = 0
        if rec["kind"] and "LIKELY QUESTION BANK" in rec["kind"]:
            boost = 100
        elif rec["kind"] and ("Flash" in rec["kind"] or "ZIP" in rec["kind"]
                              or "Cabinet" in rec["kind"]):
            boost = 10
        rec["rank"] = maxscore + boost
        scored.append(rec)

    scored.sort(key=lambda r: (-r["rank"], -r["n_strings"]))

    # ---- ranked candidates --------------------------------------------------
    say()
    say("--- Ranked candidates (question-likelihood) ---")
    for i, rec in enumerate(scored[:25], 1):
        rel = os.path.relpath(rec["path"], root)
        say("[%2d] %s  (%.2f MB)" % (i, rel, rec["size"] / 1048576))
        if rec["kind"]:
            say("     kind    : %s" % rec["kind"])
        say("     strings : %d (8-bit %d / UTF-16 %d)"
            % (rec["n_strings"], len(rec["strings8"]), len(rec["strings16"])))
        if rec["error"]:
            say("     note    : %s" % rec["error"])
        for sc, s in rec["top"]:
            say("     %3d | %s" % (sc, s[:160]))
        for h in rec["hints"][:5]:
            say("     hint    : %s" % h[:220])
        say()

    # ---- database handling --------------------------------------------------
    sqlite_dumps = []
    access_found = []
    say("--- Database findings ---")
    for rec in scored:
        kind = rec["kind"] or ""
        if "SQLite database" in kind:
            say("* SQLite DB: %s -> dumping tables to CSV" % rec["path"])
            made = dump_sqlite(rec["path"], outdir)
            sqlite_dumps.append((rec["path"], made))
            for t, fn in made:
                say("    table %-30s -> %s" % (t, os.path.relpath(fn, outdir)))
        elif "Access" in kind and "lock" not in kind:
            access_found.append(rec["path"])
            made = dump_access_mdbtools(rec["path"], outdir)
            if made is None:
                say("* Access DB: %s" % rec["path"])
                say("    mdbtools not found. On Linux/WSL:  sudo apt install mdbtools")
                say("    then:  mdb-tables -1 \"%s\"   and   mdb-export \"%s\" <TABLE> > table.csv"
                    % (rec["path"], rec["path"]))
                say("    On Windows: MDB Viewer Plus, or Access PassView if it is password-protected.")
            else:
                say("* Access DB: %s -> dumping tables to CSV" % rec["path"])
                for t, fn in made:
                    say("    table %-30s -> %s" % (t, os.path.relpath(fn, outdir)))
    if not sqlite_dumps and not access_found:
        say("(no readable Access/SQLite database identified by signature)")

    # ---- write outputs ------------------------------------------------------
    wrote = 0
    for rec in scored[:80]:
        if rec["n_strings"] == 0:
            continue
        fn = unique_path(strdir, flat_name(rec["path"], root), ".strings.txt")
        try:
            with open(fn, "w", encoding="utf-8", errors="replace") as f:
                f.write("# %s\n# kind: %s\n\n" % (rec["path"], rec["kind"]))
                f.write("## UTF-16LE strings\n")
                f.write("\n".join(rec["strings16"]))
                f.write("\n\n## 8-bit strings\n")
                f.write("\n".join(rec["strings8"]))
            wrote += 1
        except OSError:
            pass

    rep = os.path.join(outdir, "report.txt")
    with open(rep, "w", encoding="utf-8", errors="replace") as f:
        f.write("\n".join(report_lines))

    say()
    say("--- Output ---")
    say("report : %s" % rep)
    say("strings: %s  (%d files)" % (strdir, wrote))

    say()
    say("--- Next steps ---")
    say("1. Access DB found? Export tables (see above) and look for Question/Quiz tables.")
    say("2. .exe/.ocx with question hits? It embeds text (VB6=UTF-16, Delphi=UTF-16,")
    say("   .NET=use ILSpy/dnSpy). Resource Hacker can dump embedded resources.")
    say("3. Nothing obvious? Run the game and use Process Monitor (ProcMon): filter")
    say("   Path contains <game folder> and Operation is ReadFile, then click through a")
    say("   question -- the file(s) read at that moment hold the data.")
    say("4. Password-protected Access DB? The password is often recoverable from the")
    say("   .exe strings (see 'hint:' lines above) or with NirSoft Access PassView.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
