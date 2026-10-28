#!/usr/bin/env python3
"""
finalize.py - approve the reviewed draft and publish it as the final, shareable version.
Python standard library only, runs locally, no internet.

Usage (run from the project folder):
  python3 src/finalize.py              -> approves only if no CHECK groups are left
  python3 src/finalize.py --override   -> approve anyway (you decided the rest are fine)

Reads:
  data/interim/customer-bugs.draft.txt     the draft from src/redact_slack.py
  config/allow.txt, config/terms.txt       (for the checks and the record)

Writes:
  data/final/customer-bugs.final.txt       approved cleaned data - the ONLY file you share
  data/final/customer-bugs.approval.txt    when / how it was approved (counts only, no data)

Refuses when:
  - the draft still has CHECK groups (same rules as src/summarize_review.py), unless --override
  - config/terms.txt or the raw export changed AFTER the draft was made
    (re-run src/redact_slack.py first, otherwise your latest terms are not applied)
"""
import argparse
import datetime
import hashlib
import os
import re
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from summarize_review import analyze, resolve_allow, rel, PROJECT_DIR  # noqa: E402

DRAFT = os.path.join(PROJECT_DIR, "data", "interim", "customer-bugs.draft.txt")
RAW = os.path.join(PROJECT_DIR, "data", "raw", "customer-bugs.txt")
TERMS = os.path.join(PROJECT_DIR, "config", "terms.txt")
FINAL_DIR = os.path.join(PROJECT_DIR, "data", "final")
FINAL = os.path.join(FINAL_DIR, "customer-bugs.final.txt")
RECORD = os.path.join(FINAL_DIR, "customer-bugs.approval.txt")

NUMBERED = re.compile(r"\b([A-Z]+)_\d{3}\b")
FIXED = re.compile(r"\[(SECRET|SLACK_LINK|SLACK_FILE|NAME|CARD|PAN|AADHAAR|IP|PRIVATE_KEY)\]")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def count_entries(path):
    if not path or not os.path.isfile(path):
        return 0
    with open(path, encoding="utf-8") as f:
        return sum(1 for line in f if line.strip() and not line.strip().startswith("#"))


def main():
    ap = argparse.ArgumentParser(description="Approve the reviewed draft as the final, shareable version.")
    ap.add_argument("--override", action="store_true",
                    help="approve even if CHECK groups remain (you reviewed them and they are fine)")
    args = ap.parse_args()

    if not os.path.isfile(DRAFT):
        sys.exit(f"No draft found at {rel(DRAFT)}. Run src/redact_slack.py first.")

    # 1. the draft must reflect the latest terms.txt and raw export
    draft_time = os.path.getmtime(DRAFT)
    for path, what in ((TERMS, "config/terms.txt"), (RAW, "the raw export")):
        if os.path.isfile(path) and os.path.getmtime(path) > draft_time:
            sys.exit(f"NOT APPROVED: {what} changed after the draft was made.\n"
                     f"Run src/redact_slack.py again, then src/summarize_review.py, then this.")

    # 2. same checks as the summary
    allow = resolve_allow(None)
    groups, flagged_lines, _ = analyze(DRAFT, allow)
    to_check = [g for g in groups.values() if not g["safe"]]
    if to_check and not args.override:
        print(f"NOT APPROVED: {len(to_check)} CHECK group(s) still open "
              f"({sum(g['count'] for g in to_check)} occurrences).")
        print("Resolve them via config/terms.txt or config/allow.txt (see data/private/customer-bugs.summary.txt),")
        print("or, if you have reviewed them and they are fine:  python3 src/finalize.py --override")
        sys.exit(1)

    # 3. publish
    os.makedirs(FINAL_DIR, exist_ok=True)
    shutil.copyfile(DRAFT, FINAL)

    with open(FINAL, encoding="utf-8", errors="replace") as f:
        text = f.read()
    numbered = {}
    for m in NUMBERED.finditer(text):
        numbered.setdefault(m.group(1), set()).add(m.group(0))
    fixed = {}
    for m in FIXED.finditer(text):
        fixed[m.group(1)] = fixed.get(m.group(1), 0) + 1

    now = datetime.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %z")
    with open(RECORD, "w", encoding="utf-8") as f:
        f.write("Approval record - counts only, no personal data. Safe to share with the final file.\n\n")
        f.write(f"Approved at        : {now}\n")
        f.write(f"Override used      : {'YES - ' + str(len(to_check)) + ' CHECK group(s) accepted as-is' if to_check else 'no'}\n")
        f.write(f"Final file         : {rel(FINAL)}\n")
        f.write(f"Final SHA-256      : {sha256(FINAL)}\n")
        f.write(f"Lines              : {text.count(chr(10))}\n")
        f.write(f"Terms entries used : {count_entries(TERMS)}\n")
        f.write(f"Allow entries used : {count_entries(allow)}\n\n")
        f.write("Distinct placeholders in the final file:\n")
        for kind in sorted(numbered):
            f.write(f"  {kind:<10} {len(numbered[kind])}\n")
        if not numbered:
            f.write("  none\n")
        f.write("Fixed redactions in the final file:\n")
        for kind in sorted(fixed):
            f.write(f"  [{kind}] {fixed[kind]}\n")
        if not fixed:
            f.write("  none\n")

    print("APPROVED")
    print(f"Final file   : {rel(FINAL)}   <- the only file to share")
    print(f"Record       : {rel(RECORD)}")
    if to_check:
        print(f"Note         : approved with --override ({len(to_check)} CHECK group(s) accepted)")


if __name__ == "__main__":
    main()