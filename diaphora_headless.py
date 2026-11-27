#!/usr/bin/env python3
"""Headless Diaphora CLI powered by Hex-Rays IDALib.

Exports binaries to Diaphora SQLite databases without opening the IDA GUI,
diffs two exports, and prints a concise patch-triage summary.
"""

from __future__ import annotations

import argparse
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

__version__ = "0.1.0"


def find_diaphora_dir() -> str:
    """Locate the Diaphora source tree (containing diaphora.py and diaphora_ida.py)."""
    here = Path(__file__).resolve().parent
    candidates = [
        os.environ.get("DIAPHORA_DIR"),
        str(here / "vendor" / "diaphora"),
        str(here.parent / "diaphora"),
        str(Path.home() / "Desktop" / "diaphora"),
        str(Path.home() / "diaphora"),
        "/opt/diaphora",
        "/usr/local/share/diaphora",
    ]
    for cand in candidates:
        if not cand:
            continue
        p = Path(cand).expanduser()
        if (p / "diaphora.py").is_file() and (p / "diaphora_ida.py").is_file():
            return str(p)
    raise SystemExit(
        "Diaphora source tree not found. Clone https://github.com/joxeankoret/diaphora "
        "and set DIAPHORA_DIR=/path/to/diaphora (or place it in vendor/diaphora)."
    )


def cmd_export(args: argparse.Namespace) -> int:
    os.environ["DIAPHORA_AUTO"] = "1"
    os.environ["DIAPHORA_EXPORT_FILE"] = os.path.abspath(args.out)
    os.environ["DIAPHORA_USE_DECOMPILER"] = "0" if args.no_decompiler else "1"
    if args.project_script:
        os.environ["DIAPHORA_PROJECT_SCRIPT"] = os.path.abspath(args.project_script)

    import idapro
    import diaphora_ida  # noqa: F401

    rc = idapro.open_database(
        os.path.abspath(args.binary),
        run_auto_analysis=not args.no_auto,
        args=args.ida_args,
    )
    if rc != 0:
        print(f"[diaphora-headless] open_database failed (code {rc}): {args.binary}", file=sys.stderr)
        return 1

    # diaphora_ida.main() exports and calls idaapi.qexit(0) when DIAPHORA_AUTO is set.
    diaphora_ida.main()
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    from diaphora import CBinDiff, sqlite3_connect

    out = os.path.abspath(args.out)
    if os.path.exists(out):
        os.remove(out)
    bd = CBinDiff(os.path.abspath(args.db1))
    bd.ignore_all_names = False
    bd.db = sqlite3_connect(os.path.abspath(args.db1))
    bd.diff(os.path.abspath(args.db2))
    bd.save_results(out)
    print(f"[diaphora-headless] diff saved: {out}")
    return cmd_summary(argparse.Namespace(db=out, limit=args.limit))


def fmt_ea(value: object) -> str:
    s = str(value)
    return s if s.startswith("0x") else f"0x{s}"


def cmd_summary(args: argparse.Namespace) -> int:
    con = sqlite3.connect(args.db)
    cur = con.cursor()
    counts = dict(cur.execute("select type, count(*) from results group by type").fetchall())
    unmatched = dict(cur.execute("select type, count(*) from unmatched group by type").fetchall())

    cfg = cur.execute("select main_db, diff_db from config limit 1").fetchone()
    print("\n=== Diaphora Summary ===")
    if cfg:
        print(f"BEFORE (main): {cfg[0]}")
        print(f"AFTER  (diff): {cfg[1]}")
    print(f"Best (equal):        {counts.get('best', 0)}")
    print(f"Partial (modified?): {counts.get('partial', 0)}")
    print(f"Unreliable:          {counts.get('unreliable', 0)}")
    # Note: Diaphora's unmatched table stores main-db unmatched as 'secondary' and diff-db unmatched as 'primary'.
    print(f"Only in BEFORE:      {unmatched.get('secondary', 0)}")
    print(f"Only in AFTER (new): {unmatched.get('primary', 0)}")

    limit = args.limit
    rows = cur.execute(
        """select address, name, address2, name2, ratio, description
           from results where type in ('partial', 'unreliable')
           order by cast(ratio as real) asc limit ?""",
        (limit,),
    ).fetchall()
    if rows:
        print(f"\n--- Top changed functions (lowest similarity first, limit {limit}) ---")
        for a1, n1, a2, n2, ratio, desc in rows:
            print(f"  {float(ratio):.3f}  {n1} ({fmt_ea(a1)}) -> {n2} ({fmt_ea(a2)})  [{desc}]")

    for kind, label in (("primary", "New functions in AFTER"), ("secondary", "Removed functions in AFTER")):
        urows = cur.execute(
            "select address, name from unmatched where type = ? limit ?", (kind, limit)
        ).fetchall()
        if urows:
            print(f"\n--- {label} (limit {limit}) ---")
            for addr, name in urows:
                print(f"  {fmt_ea(addr)}  {name}")
    con.close()
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    before = Path(args.before).resolve()
    after = Path(args.after).resolve()
    if before.name == after.name:
        tag1 = before.parent.name if before.parent.name != after.parent.name else "before"
        tag2 = after.parent.name if before.parent.name != after.parent.name else "after"
        db1 = out_dir / f"{tag1}_{before.name}.sqlite"
        db2 = out_dir / f"{tag2}_{after.name}.sqlite"
        diff_db = out_dir / f"{tag1}_vs_{tag2}_{before.stem}.diaphora"
    else:
        db1 = out_dir / f"{before.name}.sqlite"
        db2 = out_dir / f"{after.name}.sqlite"
        diff_db = out_dir / f"{before.stem}_vs_{after.stem}.diaphora"

    extra = ["--no-decompiler"] if args.no_decompiler else []
    if args.ida_args:
        extra += ["--ida-args", args.ida_args]
    if args.project_script:
        extra += ["--project-script", args.project_script]

    for src, dst in ((before, db1), (after, db2)):
        if dst.exists() and not args.force:
            print(f"[diaphora-headless] reusing existing export: {dst}")
            continue
        print(f"[diaphora-headless] exporting {src} -> {dst}", flush=True)
        rc = subprocess.call([sys.executable, sys.argv[0], "export", str(src), str(dst), *extra])
        if rc != 0:
            return rc

    return cmd_diff(argparse.Namespace(db1=str(db1), db2=str(db2), out=str(diff_db), limit=args.limit))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Headless Diaphora (IDALib) diffing helper",
        epilog="Environment: DIAPHORA_DIR=/path/to/diaphora, IDADIR=/path/to/ida",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_exp = sub.add_parser("export", help="Export a binary to a Diaphora SQLite DB via IDALib")
    p_exp.add_argument("binary")
    p_exp.add_argument("out")
    p_exp.add_argument("--no-decompiler", action="store_true", help="Skip Hex-Rays pseudocode export")
    p_exp.add_argument("--no-auto", action="store_true", help="Do not wait for auto-analysis")
    p_exp.add_argument("--ida-args", default=None, help="Extra IDA command-line arguments")
    p_exp.add_argument("--project-script", default=None, help="Diaphora project Python script")
    p_exp.set_defaults(func=cmd_export)

    p_diff = sub.add_parser("diff", help="Diff two exported Diaphora SQLite DBs")
    p_diff.add_argument("db1")
    p_diff.add_argument("db2")
    p_diff.add_argument("-o", "--out", required=True)
    p_diff.add_argument("--limit", type=int, default=25)
    p_diff.set_defaults(func=cmd_diff)

    p_sum = sub.add_parser("summary", help="Summarize an existing .diaphora diff DB")
    p_sum.add_argument("db")
    p_sum.add_argument("--limit", type=int, default=25)
    p_sum.set_defaults(func=cmd_summary)

    p_run = sub.add_parser("run", help="Export two binaries, diff them, and print a summary")
    p_run.add_argument("before")
    p_run.add_argument("after")
    p_run.add_argument("-d", "--out-dir", default="diaphora_out")
    p_run.add_argument("--no-decompiler", action="store_true")
    p_run.add_argument("--ida-args", default=None)
    p_run.add_argument("--project-script", default=None)
    p_run.add_argument("--force", action="store_true", help="Re-export even if SQLite DBs exist")
    p_run.add_argument("--limit", type=int, default=25)
    p_run.set_defaults(func=cmd_run)

    args = parser.parse_args()
    if args.cmd in ("export", "diff", "run"):
        diaphora_dir = find_diaphora_dir()
        if diaphora_dir not in sys.path:
            sys.path.insert(0, diaphora_dir)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
