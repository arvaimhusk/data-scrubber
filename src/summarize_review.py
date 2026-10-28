#!/usr/bin/env python3
"""
summarize_review.py - turn hundreds of "possible leftover" lines into a short list of
decisions. Reads the DRAFT that redact_slack.py wrote (it does not change it). Python
standard library only, runs locally, no internet.

Usage (run from the project folder; no file names needed):
  python3 src/summarize_review.py

Reads:
  data/interim/customer-bugs.draft.txt   written by src/redact_slack.py
  config/allow.txt                     checked, harmless items (used automatically if it exists)

Writes:
  data/private/customer-bugs.summary.txt   grouped list of what is left to decide.   KEEP PRIVATE.

How it works
  Every flagged line is checked again and the suspicious piece is pulled out:
    - a word after a greeting ("Hi Priya")            -> grouped by that word
    - anything with an @ in it                         -> grouped by the token
    - a number with 7+ digits                          -> grouped by its FORMAT, e.g. all
                                                          "Rec + letters + digits" IDs together;
                                                          links are grouped by WEBSITE
  Each group is labelled "probably safe" (record IDs, timestamps, UUIDs, @here, "Hi Team"...)
  or "CHECK". Every CHECK group comes with two ready-made lines - copy ONE:
    - it is personal/customer data  -> its terms.txt line, then re-run redact_slack.py
    - it is harmless                -> its allow.txt line (e.g. group:Link: app.example.com)

allow.txt accepts:  regex:... (a pattern),  group:<name> (a whole group),  or simply an EXAMPLE
pasted from the summary - it allows that item AND the whole group it belongs to (same website,
same number format). The summary lists every group it learned this way.
"""
import argparse
import os
import re
import sys

GREETING = re.compile(r"\b(?:[Hh]i|[Hh]ello|[Hh]ey|[Tt]hanks|[Tt]hank you|[Cc]c|[Dd]ear)\s+([A-Z][a-z]{2,})")
AT_TOKEN = re.compile(r"[^\s<>()|,;\"'`]*@[^\s<>()|,;\"'`]*")
LONG_NUM_TOKEN = re.compile(r"[^\s<>()|,;\"'`]*\d{7,}[^\s<>()|,;\"'`]*")

SAFE_GREETING_WORDS = {
    "team", "all", "everyone", "everybody", "folks", "guys", "there", "both", "again", "sir",
    "madam", "mam", "maam", "bhai", "devs", "dev", "support", "ops", "product", "engineering",
    "customer", "client", "for", "you", "much", "this", "the", "and", "please", "sales", "qa",
}
SAFE_AT = {"@here", "@channel", "@everyone"}

# (label, regex on the token, is_safe)  - checked in this order; links are handled separately
NUMBER_KINDS = [
    ("Slack List record ID (Rec...)", re.compile(r"(?:^|[=(])Rec[0-9A-Za-z]{6,}"), True),
    ("Slack timestamp (1712345678.123456)", re.compile(r"\b\d{10}\.\d{6}\b"), True),
    ("UUID / request ID", re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"), True),
    ("Unix time (10/13 digits)", re.compile(r"^(?:1[5-9]\d{8}|1[5-9]\d{11})$"), True),
    ("Git commit hash", re.compile(r"^(?=[0-9a-f]*[a-f])[0-9a-f]{7,40}$"), True),
    ("Version / build number", re.compile(r"^v?\d+(?:\.\d+){2,}$"), True),
]
MOBILE_LABEL = "10-digit number starting 6-9 - looks like an Indian mobile"
MOBILE = re.compile(r"(?<!\d)[6-9]\d{9}(?!\d)")
# A web address at the start of the token, with or without https:// - "manage.example.io/..."
LINK_HOST = re.compile(r"^(?:https?://)?([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+)(?=[/?#:])")
PLACEHOLDER_PART = re.compile(r"[A-Z]+_\d{3}")


def host_regex(host):
    """Regex for a host; placeholder parts (CUSTOMER_072) match anything, so the line still
    works in redact_slack.py, which sees the text before every placeholder is in place."""
    parts = [r"[^/\s>|]+" if PLACEHOLDER_PART.fullmatch(p) else re.escape(p) for p in host.split(".")]
    return r"\.".join(parts)


def shape_regex(shp):
    """Turn a shape like 'a{6}.9{10}' back into a regex that matches every token of that shape."""
    out = []
    for ch, count in re.findall(r"(.)(?:\{(\d+)\})?", shp):
        cls = {"9": r"\d", "A": "[A-Z]", "a": "[a-z]"}.get(ch, re.escape(ch))
        out.append(cls + (f"{{{count}}}" if count else ""))
    return r"(?<![\w])" + "".join(out) + r"(?![\w])"


def classify_number(tok):
    """-> (label, is_safe, line to hide the whole group via config/terms.txt or None)."""
    for label, rx, safe in NUMBER_KINDS:
        if rx.search(tok):
            return label, safe, None
    m = LINK_HOST.match(tok)
    if m and re.search(r"[A-Za-z]", m.group(1)):
        host = m.group(1)
        return f"Link: {host}", False, rf"regex:(?:https?://)?{host_regex(host)}[/?#:][^\s>|]*"
    if MOBILE.search(tok):
        return MOBILE_LABEL, False, r"regex:(?<!\d)[6-9]\d{9}(?!\d)"
    shp = shape(tok)
    return f"Unknown format {shp}", False, "regex:" + shape_regex(shp)


def shape(token: str) -> str:
    """Format of a token with the actual characters hidden: 'Rec0AZZL678068' -> 'Aa{2}9A{4}9{6}'."""
    out, prev, run = [], None, 0
    for ch in token:
        c = "9" if ch.isdigit() else "A" if ch.isupper() else "a" if ch.islower() else ch
        if c == prev:
            run += 1
        else:
            if prev is not None:
                out.append(prev + (f"{{{run}}}" if run > 1 else ""))
            prev, run = c, 1
    if prev is not None:
        out.append(prev + (f"{{{run}}}" if run > 1 else ""))
    return "".join(out)


def load_allow(path, report=None):
    """allow.txt lines:
         regex:...               a pattern
         group:<name>            a whole group, as named in the summary
         anything else           an EXAMPLE: the exact item, plus the whole group it belongs to.
                                 Paste any e.g. line from the summary - links count for their
                                 whole website, numbers for their whole format, greetings for the
                                 word, @-tokens for that token.
    report (optional list) receives (allow.txt line number, group learned from an example)."""
    exact, patterns, whole_groups = set(), [], set()
    if not path:
        return exact, patterns, whole_groups
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("regex:"):
                try:
                    patterns.append(re.compile(line[len("regex:"):]))
                except re.error as e:
                    sys.exit(f"{path}, line {lineno}: invalid regex ({e}). Fix or remove that line.")
            elif line.startswith("group:"):
                whole_groups.add(line[len("group:"):].strip().lower())
            else:
                exact.add(line.lower())
                # learn from the example: the same extraction the summary uses
                for m in GREETING.finditer(line):
                    exact.add(m.group(1).lower())
                for m in AT_TOKEN.finditer(line):
                    if re.search(r"\S@[A-Za-z]", m.group(0)):
                        exact.add(m.group(0).lower())
                for m in LONG_NUM_TOKEN.finditer(line):
                    label = classify_number(m.group(0))[0]
                    if label.lower() not in whole_groups and report is not None:
                        report.append((lineno, label))
                    whole_groups.add(label.lower())
    return exact, patterns, whole_groups


def allowed(token, exact, patterns):
    return token.lower() in exact or any(p.search(token) for p in patterns)


# Project layout - relative to the project folder (the parent of src/).
PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_DRAFT = os.path.join(PROJECT_DIR, "data", "interim", "customer-bugs.draft.txt")
PRIVATE_DIR = os.path.join(PROJECT_DIR, "data", "private")
DEFAULT_ALLOW = os.path.join(PROJECT_DIR, "config", "allow.txt")


def rel(path):
    """Path as shown on screen: relative to the project folder."""
    try:
        return os.path.relpath(path, PROJECT_DIR)
    except ValueError:                       # e.g. a different drive on Windows
        return os.path.abspath(path)


def analyze(path, allow_path=None):
    """Scan a cleaned file. Returns (groups, flagged_line_numbers, allowed_hits).
    Shared with finalize.py so both use exactly the same rules."""
    exact, patterns, whole_groups = load_allow(allow_path)
    # group key -> {"section", "label", "safe", "count", "lines", "examples", "allow_line", "hide_line"}
    groups = {}
    flagged_lines, allowed_hits = set(), 0

    def add(section, key, label, safe, lineno, example, allow_line, hide_line):
        g = groups.setdefault((section, key), {"section": section, "label": label, "safe": safe,
                                               "count": 0, "lines": [], "examples": [],
                                               "allow_line": allow_line, "hide_line": hide_line})
        g["count"] += 1
        if len(g["lines"]) < 8 and lineno not in g["lines"]:
            g["lines"].append(lineno)
        if example not in g["examples"] and len(g["examples"]) < 3:
            g["examples"].append(example)

    with open(path, encoding="utf-8", errors="replace") as f:
        for n, line in enumerate(f, 1):
            line = line.rstrip("\n")

            for m in GREETING.finditer(line):
                word = m.group(1)
                if allowed(word, exact, patterns) or word.lower() in whole_groups:
                    allowed_hits += 1
                    continue
                flagged_lines.add(n)
                safe = word.lower() in SAFE_GREETING_WORDS
                add("names", word.lower(), word, safe, n, line.strip()[:160], word, word)

            for m in AT_TOKEN.finditer(line):
                tok = m.group(0)
                if not re.search(r"\S@[A-Za-z]", tok):
                    continue
                if allowed(tok, exact, patterns) or tok.lower() in whole_groups:
                    allowed_hits += 1
                    continue
                flagged_lines.add(n)
                safe = tok.lower().strip(".:!?*") in SAFE_AT
                add("at", tok.lower(), tok, safe, n, line.strip()[:160], tok, tok)

            for m in LONG_NUM_TOKEN.finditer(line):
                tok = m.group(0)
                label, safe, hide_line = classify_number(tok)
                if allowed(tok, exact, patterns) or label.lower() in whole_groups:
                    allowed_hits += 1
                    continue
                flagged_lines.add(n)
                add("numbers", label, label, safe, n, tok[:80], f"group:{label}", hide_line)
    return groups, flagged_lines, allowed_hits


def resolve_allow(allow_arg):
    """--allow given -> that file; otherwise config/allow.txt if it exists; otherwise none."""
    if allow_arg is None and os.path.isfile(DEFAULT_ALLOW):
        return DEFAULT_ALLOW
    return allow_arg


def main():
    ap = argparse.ArgumentParser(description="Group possible leftovers in a cleaned file into a short decision list.")
    ap.add_argument("cleaned", nargs="?", default=DEFAULT_DRAFT,
                    help=f"the draft written by redact_slack.py (default: {rel(DEFAULT_DRAFT)})")
    ap.add_argument("--allow", default=None,
                    help=f"file of checked, harmless tokens (default: {rel(DEFAULT_ALLOW)} if it exists)")
    args = ap.parse_args()
    if not os.path.isfile(args.cleaned):
        ap.error(f"file not found: {os.path.abspath(args.cleaned)}\n"
                 "Run src/redact_slack.py first - it creates this file.")
    args.allow = resolve_allow(args.allow)
    if args.allow and not os.path.isfile(args.allow):
        ap.error(f"allow file not found: {os.path.abspath(args.allow)}")

    groups, flagged_lines, allowed_hits = analyze(args.cleaned, args.allow)
    learned = []                                    # (allow.txt line, group) - for the report only
    load_allow(args.allow, report=learned)

    name = os.path.splitext(os.path.basename(args.cleaned))[0]
    for suffix in (".draft", ".clean"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
    os.makedirs(PRIVATE_DIR, exist_ok=True)
    out_path = os.path.join(PRIVATE_DIR, name + ".summary.txt")

    sections = [
        ("names", "WORDS AFTER A GREETING (\"Hi Priya\", \"Thanks Rohan\")",
         "If it is a person or customer -> add the word to config/terms.txt. If not -> add it to config/allow.txt."),
        ("at", "TOKENS WITH AN @",
         "A leftover handle or partial email -> add to config/terms.txt. Code/@here/etc -> config/allow.txt."),
        ("numbers", "LONG NUMBERS, GROUPED BY FORMAT",
         "IDs, timestamps, hashes are safe to keep. Phone/account numbers -> add a regex: line to config/terms.txt."),
    ]
    to_check = [g for g in groups.values() if not g["safe"]]
    probably_safe = [g for g in groups.values() if g["safe"]]

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("KEEP THIS FILE PRIVATE - examples may contain data the redactor missed.\n\n")
        f.write(f"{len(flagged_lines)} flagged lines -> {len(groups)} groups: "
                f"{len(to_check)} to CHECK, {len(probably_safe)} probably safe"
                f"{f', {allowed_hits} hits already in allow.txt' if args.allow else ''}.\n")
        f.write("Decide each CHECK group ONCE and copy ONE of its two ready-made lines:\n"
                "  harmless  -> the allow.txt line, or just paste one of its e.g. lines into allow.txt\n"
                "               (either way the WHOLE group is allowed; then re-run src/summarize_review.py)\n"
                "  sensitive -> the terms.txt line  (then re-run src/redact_slack.py and src/summarize_review.py)\n"
                "'probably safe' groups need nothing.\n")
        if learned:
            f.write("\nWhole groups allowed because an example of them is in allow.txt:\n")
            for lineno, label in learned:
                f.write(f"  allow.txt line {lineno:>3}  ->  {label}\n")
        for sec, title, advice in sections:
            sec_groups = sorted((g for g in groups.values() if g["section"] == sec),
                                key=lambda g: (g["safe"], -g["count"]))
            if not sec_groups:
                continue
            f.write(f"\n\n=== {title} ===\n{advice}\n\n")
            for g in sec_groups:
                tag = "probably safe" if g["safe"] else "CHECK"
                lines = ", ".join(map(str, g["lines"])) + (" ..." if g["count"] > len(g["lines"]) else "")
                f.write(f"[{tag:>13}] {g['count']:>5} x  {g['label']}\n")
                f.write(f"{'':16}lines: {lines}\n")
                for ex in g["examples"]:
                    f.write(f"{'':16}e.g. {ex}\n")
                if not g["safe"]:
                    f.write(f"{'':16}harmless?  add to config/allow.txt :  {g['allow_line']}\n")
                    if g["hide_line"]:
                        f.write(f"{'':16}sensitive? add to config/terms.txt :  {g['hide_line']}\n")
                f.write("\n")

    # screen output: counts only, never the data itself
    print(f"Allow list   : {rel(args.allow) if args.allow else 'none'}")
    print(f"Summary      : {rel(out_path)}   (KEEP PRIVATE)")
    print(f"Flagged lines: {len(flagged_lines)}")
    print(f"Groups       : {len(groups)}  ({len(to_check)} to CHECK, {len(probably_safe)} probably safe)")
    if args.allow:
        print(f"Already allowed (skipped): {allowed_hits}")
        print(f"Groups learned from examples in allow.txt: {len(learned)}  (listed at the top of the summary)")


if __name__ == "__main__":
    main()