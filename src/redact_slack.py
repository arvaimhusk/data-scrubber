#!/usr/bin/env python3
"""
redact_slack.py - clean a slackdump .txt export LOCALLY.
No LLM, no internet, Python standard library only.

Usage (run from the project folder; no file names needed):
  python3 src/redact_slack.py --customer-scope file
  python3 src/redact_slack.py --selftest
  python3 src/redact_slack.py path/to/OTHER.txt         (only if you ever need a different input)

Reads:
  data/raw/customer-bugs.txt          your slackdump export (never modified)
  config/terms.txt                    names / IDs to hide (used automatically if it exists)

Writes (overwritten on every run):
  data/interim/customer-bugs.draft.txt    the cleaned DRAFT - may still need review.  PRIVATE.
  data/private/customer-bugs.mapping.csv  placeholder -> original value.   KEEP PRIVATE.
  data/private/customer-bugs.review.txt   before/after samples + possible leftovers.   KEEP PRIVATE.
The approved, shareable version is created only by src/finalize.py.

What gets replaced (in this order):
  1. Private keys, API keys/tokens (Slack, GitHub, AWS, OpenAI-style, JWT, Bearer),
     "password: ...", "api_key=...", secret-looking URL query params      -> [SECRET]
  2. Slack file links and any workspace link (messages, lists, canvases)  -> [SLACK_FILE] / [SLACK_LINK]
     (the "?record_id=..." part of a link is kept, so ticket/record IDs survive)
  3. Email addresses (whole address, domain included)                   -> EMAIL_001, EMAIL_002 ...
  4a. Customer names LEARNED from each issue's own *Customer* / *Company* / *Account* /
     *Client* field are searched case-insensitively across that whole issue (its
     *Details*, thread replies, etc.) and replaced everywhere. Short forms are caught too:
     "Globex Technologies Pvt Ltd" also hides "globex technologies" and "Globex".
     --customer-scope file  searches the whole file instead of just that issue.  -> CUSTOMER_001 ...
  4b. config/terms.txt: plain names (customers, people)                 -> CUSTOMER_001 ...
      regex: lines (links, number formats - e.g. from the summary)      -> HIDDEN_001 ...
  5. Names of people who posted (read from message headers), Slack
     mentions <@U...> and user IDs U...                                 -> USER_001 ...
  6. Labelled fields, either "Customer: Acme" on one line, or a bold label
     with the value on the next line (Slack Lists / workflow posts):
         *Customer*
         Acme Corp
     Customer/company/account/client fields                             -> CUSTOMER_nnn
     Person fields (reported by, contact, owner, email...)              -> [NAME]
  7. Card numbers (Luhn-checked), Aadhaar (spaced form), PAN            -> [CARD] / [AADHAAR] / [PAN]
  8. Phone numbers (+country code, 555-123-4567 style, Indian mobiles)  -> PHONE_001 ...
  9. IPv4 addresses                                                     -> [IP]

The same original value always gets the same placeholder, so you can still count
"how many reports came from CUSTOMER_004" without knowing who that is.

Deliberately LEFT ALONE: message dates/timestamps, plain long numbers, commit hashes,
ticket/record IDs (Rec...), version numbers, "Customer-reported ..." style text, localhost:3000 etc.
"""
import argparse
import csv
import os
import random
import re
import sys
from collections import Counter, defaultdict

# ---------------------------------------------------------------- patterns

PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)

SECRET_PATTERNS = [re.compile(p) for p in (
    r"\bxox[abposr]-[A-Za-z0-9-]{10,}",                       # Slack tokens
    r"\bxapp-[A-Za-z0-9-]{10,}",                              # Slack app tokens
    r"\bgh[pousr]_[A-Za-z0-9]{20,}",                          # GitHub tokens
    r"\bgithub_pat_[A-Za-z0-9_]{20,}",                        # GitHub fine-grained tokens
    r"\bsk-[A-Za-z0-9_-]{20,}",                               # sk-... style API keys
    r"\bAKIA[0-9A-Z]{16}\b",                                  # AWS access key IDs
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}",  # JWTs
    r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}",                # Bearer tokens
)]
KV_SECRET = re.compile(
    r"(?i)\b((?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|token|client[_-]?secret)"
    r"\b\s*[:=]\s*)(\S+)")
QUERY_SECRET = re.compile(
    r"(?i)([?&](?:token|key|api_?key|access_token|auth|sig|signature|password|code)=)[^&\s>)\]]+")

SLACK_FILE = re.compile(r"https?://files\.slack\.com/[^\s>|)\]]+")
# Any other workspace link (archives, lists, canvases, docs...). Only the part before "?" is
# replaced, so query values like ?record_id=Rec00AASZL678123 survive for linking.
SLACK_LINK = re.compile(r"https?://[A-Za-z0-9-]+\.slack\.com/[^\s>|)\]?]*")

EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")

# Message header, e.g. "> Alice Kumar [U05Q8BKMNLQ] @ 15/10/2026 10:22:33 Z:"
HEADER = re.compile(r"^[ \t|]*(?:>\s*)?(?P<name>[^\W\d_][\w .'\-]{1,59}?)\s*\[(?P<id>[UW][A-Z0-9]{6,})\]", re.M)
SLACK_MENTION = re.compile(r"<@([UW][A-Z0-9]{6,})(?:\|[^>]*)?>")
# Bare Slack user IDs. Modern IDs start with U0 / W0, which avoids ordinary words like
# "WORKFLOW2026". IDs seen in message headers or <@...> mentions are also replaced whatever
# their shape (see Redactor.redact).
SLACK_ID = re.compile(r"\b([UW]0[A-Z0-9]{6,11})\b")
# A message header line: "[U0123ABC] @ 15/04/2026" (also after names were replaced).
HEADER_LIKE = re.compile(r"\[[^\]\n]*\]\s*@\s*\d{2}/\d{2}/\d{4}")
NAME_STOP = {"support", "team", "bot", "admin", "jira", "github", "slack", "qa", "dev", "the", "customer", "user"}

# Field labels whose value is a customer/company -> CUSTOMER_nnn (so repeats can still be counted).
CUSTOMER_LABELS = r"customer|customer name|company|company name|account|account name|client|org|organisation|organization|prospect"
# Field labels whose value is a person -> [NAME].
PERSON_LABELS = (r"user|contact|contact name|contact email|owner|host|rep|reporter|reported by|requester|"
                 r"requested by|assigned to|meeting booked with|name|email|user email|prospect email")
ANY_LABEL = rf"(?:{CUSTOMER_LABELS}|{PERSON_LABELS})"

# "Customer: Acme" / "*Customer*: Acme" / "> Reported by = Bob" - at the START of a line,
# separator ":" or "=" only (so "Customer-reported ..." is never touched).
NAME_MARKER = re.compile(
    rf"(?im)^([ \t]*(?:[>|][ \t]*)*\*?(?P<label>{ANY_LABEL})\*?[ \t]*[:=][ \t]*)(?P<value>\S.*)$")

# Slack List / workflow layout: the label alone on its line (usually bold), the value on the NEXT
# non-empty line:
#     *Customer*
#     Acme Corp
NEXT_LINE_MARKER = re.compile(
    rf"(?im)^(?P<head>[ \t]*(?:[>|][ \t]*)*\*(?P<label>{ANY_LABEL})\*[ \t]*:?[ \t]*\n(?:[ \t|]*\n)*[ \t]*(?:[>|][ \t]*)*)"
    rf"(?P<value>[^\n]*\S)[ \t]*$")
LABEL_LINE = re.compile(r"^\*[^*\n]{1,40}\*\s*:?$")         # a value that is itself the next label, e.g. "*Details*"
ONLY_PLACEHOLDERS = re.compile(r"[\s,;:<>()|*-]*(?:(?:[A-Z]+_\d{3}|\[[A-Z_]+\])[\s,;:<>()|*-]*)+")

# A top-level message header starts a new issue/record. Thread replies ("|   > ...") stay
# inside the issue they belong to.  e.g.  ">  [] @ 15/04/2026 10:44:26 Z:"
TOP_HEADER = re.compile(r"^>[^\n]*\[[^\]\n]*\]\s*@\s*\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}")

# Trailing words dropped to build a customer's short form: "Globex Technologies Pvt Ltd" -> "Globex"
COMPANY_SUFFIXES = {
    "inc", "llc", "llp", "ltd", "limited", "pvt", "private", "corp", "corporation", "co", "company",
    "gmbh", "plc", "pte", "sa", "ag", "bv", "group", "holdings", "technologies", "technology", "tech",
    "solutions", "software", "systems", "labs", "services", "global", "india", "ai", "io", "hq",
}
# Never treated as a customer name on their own (too common; would garble ordinary text).
NOT_A_NAME = {
    "the", "test", "demo", "customer", "client", "company", "account", "internal", "unknown", "none",
    "n/a", "na", "tbd", "all", "multiple", "various", "general", "app", "user", "admin", "team",
}


def company_variants(name: str):
    """The full name plus shorter forms with legal/industry suffixes removed, longest first."""
    words = re.sub(r"[.,]", " ", name).split()
    variants = [" ".join(name.split())]
    while len(words) > 1 and words[-1].lower() in COMPANY_SUFFIXES:
        words = words[:-1]
        short = " ".join(words)
        if len(short) >= 4 and short.lower() not in NOT_A_NAME:
            variants.append(short)
    seen, out = set(), []
    for v in variants:
        if v.lower() not in seen and len(v) >= 3 and v.lower() not in NOT_A_NAME:
            seen.add(v.lower())
            out.append(v)
    return sorted(out, key=len, reverse=True)


def canonical_customer(name: str) -> str:
    """Key used for the placeholder, so 'Globex', 'Globex Ltd' and 'GLOBEX' share one CUSTOMER_nnn."""
    v = company_variants(name)
    return (v[-1] if v else name).lower()


def name_regex(variant: str):
    """Case-insensitive, whole-word, any whitespace between words."""
    body = r"\s+".join(re.escape(w) for w in variant.split())
    return re.compile(rf"(?i)(?<![\w@]){body}(?![\w@])")

CARD = re.compile(r"(?<![\w])(?:\d[ -]?){12,18}\d(?![\w])")
AADHAAR = re.compile(r"(?<![\w])[2-9]\d{3}[ -]\d{4}[ -]\d{4}(?![\w])")
PAN = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")

PHONE_INTL = re.compile(r"(?<![\w+])\+\d{1,3}(?:[\s.-]?\(?\d{1,5}\)?){2,5}(?![\w])")
PHONE_SEP = re.compile(r"(?<![\w.])\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?![\w.])")
PHONE_IN = re.compile(r"(?<![\w.+])0?[6-9]\d{4}[\s-]?\d{5}(?![\w.])")

IPV4 = re.compile(r"(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\w.])")

LEFTOVER_CHECKS = [
    ("'@' still present", re.compile(r"\S@[A-Za-z]")),
    ("7+ digit number", re.compile(r"\d{7,}")),
    ("greeting followed by a name", re.compile(
        r"\b(?:[Hh]i|[Hh]ello|[Hh]ey|[Tt]hanks|[Tt]hank you|[Cc]c|[Dd]ear)\s+[A-Z][a-z]{2,}")),
]


# ---------------------------------------------------------------- helpers

def luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        n = int(ch)
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    return total % 10 == 0


class Pseudonymizer:
    """Gives every distinct original value a stable placeholder like EMAIL_003."""

    def __init__(self):
        self.table = {}                       # (kind, key) -> placeholder
        self.originals = defaultdict(set)     # placeholder -> {original values}
        self.next_num = Counter()
        self.hits = Counter()

    def __call__(self, kind, original, key=None):
        k = (kind, (key or original).strip().lower())
        if k not in self.table:
            self.next_num[kind] += 1
            self.table[k] = f"{kind}_{self.next_num[kind]:03d}"
        ph = self.table[k]
        self.originals[ph].add(original.strip())
        self.hits[kind] += 1
        return ph

    def fixed(self, label):
        self.hits[label] += 1
        return f"[{label}]"

    def write_mapping(self, path):
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["placeholder", "original_values"])
            for ph in sorted(self.originals):
                w.writerow([ph, " | ".join(sorted(self.originals[ph]))])


def load_terms(path):
    """One term per line. Plain text = exact match (case-insensitive, whole word).
    Lines starting with 'regex:' are regular expressions. '#' lines are comments."""
    terms = []
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("regex:"):
                try:
                    terms.append((re.compile(line[len("regex:"):]), "HIDDEN"))
                except re.error as e:
                    sys.exit(f"{path}, line {lineno}: invalid regex ({e}). Fix or remove that line.")
            else:
                terms.append((re.compile(r"(?i)(?<!\w)" + re.escape(line) + r"(?!\w)"), "CUSTOMER"))
    return terms


# ---------------------------------------------------------------- redactor

class Redactor:
    def __init__(self, terms=None, customer_scope="record"):
        self.p = Pseudonymizer()
        # (compiled regex, placeholder kind). A bare compiled regex counts as a plain name term.
        self.terms = [t if isinstance(t, tuple) else (t, "CUSTOMER") for t in (terms or [])]
        self.customer_scope = customer_scope
        self.learned_customers = set()

    def redact(self, text: str) -> str:
        p = self.p
        names = self._collect_header_names(text)
        # Every user ID seen in a header or a <@...> mention, so bare copies of it are replaced too.
        known_ids = set(names) | {m.group(1) for m in SLACK_MENTION.finditer(text)}
        known_ids |= {m.group("id") for m in HEADER.finditer(text)}
        # Learn customer names per issue from the ORIGINAL text, before anything is replaced.
        spans = self._record_spans(text)
        lines0 = text.split("\n")
        record_customers = [self._customer_names("\n".join(lines0[a:b])) for a, b in spans]

        # 1. secrets
        text = PRIVATE_KEY.sub(lambda m: p.fixed("PRIVATE_KEY") + "\n" * m.group(0).count("\n"), text)
        for pat in SECRET_PATTERNS:
            text = pat.sub(lambda m: p.fixed("SECRET"), text)
        text = KV_SECRET.sub(lambda m: m.group(1) + p.fixed("SECRET"), text)
        text = QUERY_SECRET.sub(lambda m: m.group(1) + p.fixed("SECRET"), text)

        # 2. slack links
        text = SLACK_FILE.sub(lambda m: p.fixed("SLACK_FILE"), text)
        text = SLACK_LINK.sub(lambda m: p.fixed("SLACK_LINK"), text)

        # 3. emails (before phones, so digits inside emails can't break them)
        text = EMAIL.sub(lambda m: p("EMAIL", m.group(0)), text)

        # 4a. customer names learned from each issue's own Customer/Company field
        text = self._replace_learned_customers(text, spans, record_customers)

        # 4b. your own sensitive terms: plain names -> CUSTOMER_nnn, regex: patterns -> HIDDEN_nnn
        #     (so hidden links/numbers never inflate the customer count)
        for rx, kind in self.terms:
            if kind == "CUSTOMER":
                text = rx.sub(lambda m: p("CUSTOMER", m.group(0), key=canonical_customer(m.group(0))), text)
            else:
                text = rx.sub(lambda m: p("HIDDEN", m.group(0)), text)

        # 5. people: names from headers, mentions, user IDs -> same USER_nnn per person
        for rx, uid in self._name_patterns(names):
            text = rx.sub(lambda m, uid=uid: p("USER", m.group(0), key=uid), text)
        text = SLACK_MENTION.sub(lambda m: p("USER", m.group(0), key=m.group(1)), text)
        for uid in sorted(known_ids, key=len, reverse=True):
            text = re.sub(rf"\b{re.escape(uid)}\b", lambda m, uid=uid: p("USER", m.group(0), key=uid), text)
        text = SLACK_ID.sub(lambda m: p("USER", m.group(0), key=m.group(1)), text)

        # 6. labelled values ("Reported by: Alice", or "*Customer*" with the name on the next line)
        def labelled(prefix, label, value, whole):
            v = value.strip()
            # keep: already redacted, the next field's label, or a sentence rather than a name
            # keep: an empty field followed by the next message's header line
            if (ONLY_PLACEHOLDERS.fullmatch(v) or LABEL_LINE.match(v) or HEADER_LIKE.search(v)
                    or len(v) > 80 or len(v.split()) > 8):
                return whole
            if re.fullmatch(CUSTOMER_LABELS, label.strip().lower()):
                v = v.strip("*_ ")
                return prefix + p("CUSTOMER", v, key=canonical_customer(v))
            return prefix + p.fixed("NAME")
        text = NEXT_LINE_MARKER.sub(
            lambda m: labelled(m.group("head"), m.group("label"), m.group("value"), m.group(0)), text)
        text = NAME_MARKER.sub(
            lambda m: labelled(m.group(1), m.group("label"), m.group("value"), m.group(0)), text)

        # 7. financial / government IDs
        def card(m):
            d = re.sub(r"\D", "", m.group(0))
            return p.fixed("CARD") if 13 <= len(d) <= 19 and luhn_ok(d) else m.group(0)
        text = CARD.sub(card, text)
        text = AADHAAR.sub(lambda m: p.fixed("AADHAAR"), text)
        text = PAN.sub(lambda m: p.fixed("PAN"), text)

        # 8. phones
        def phone(m):
            digits = re.sub(r"\D", "", m.group(0))
            if len(digits) < 8:
                return m.group(0)
            return p("PHONE", m.group(0), key=digits[-10:])
        for rx in (PHONE_INTL, PHONE_SEP, PHONE_IN):
            text = rx.sub(phone, text)

        # 9. IPs
        text = IPV4.sub(lambda m: p.fixed("IP"), text)

        return text

    @staticmethod
    def _record_spans(text):
        """(start_line, end_line) for each issue. An issue runs from one top-level header to the next."""
        lines = text.split("\n")
        starts = [i for i, line in enumerate(lines) if TOP_HEADER.match(line)]
        if not starts:
            return [(0, len(lines))]
        bounds = ([0] if starts[0] > 0 else []) + starts + [len(lines)]
        return list(zip(bounds[:-1], bounds[1:]))

    @staticmethod
    def _customer_names(record_text):
        """Values of the Customer/Company/Account/Client fields in one issue."""
        found = []
        for rx in (NEXT_LINE_MARKER, NAME_MARKER):
            for m in rx.finditer(record_text):
                if not re.fullmatch(CUSTOMER_LABELS, m.group("label").strip().lower()):
                    continue
                raw = m.group("value").strip()
                v = raw.strip("*_ ").strip()
                if (LABEL_LINE.match(raw) or HEADER_LIKE.search(raw)
                        or len(v) < 3 or len(v) > 80 or len(v.split()) > 8
                        or re.search(r"[@<>]|https?://", v) or v.lower() in NOT_A_NAME):
                    continue
                found.append(v)
        return found

    def _replace_learned_customers(self, text, spans, record_customers):
        p = self.p
        lines = text.split("\n")
        if sum(b - a for a, b in spans) != len(lines):      # safety: structure changed, use whole file
            spans = [(0, len(lines))]
            record_customers = [[n for names in record_customers for n in names]]
        if self.customer_scope == "file":
            everyone = [n for names in record_customers for n in names]
            spans, record_customers = [(0, len(lines))], [everyone]

        out = []
        for (a, b), names in zip(spans, record_customers):
            chunk = "\n".join(lines[a:b])
            pats = []
            for name in names:
                self.learned_customers.add(canonical_customer(name))
                key = canonical_customer(name)
                for variant in company_variants(name):
                    pats.append((len(variant), name_regex(variant), key))
            for _, rx, key in sorted(pats, key=lambda t: -t[0]):           # longest first
                chunk = rx.sub(lambda m, key=key: p("CUSTOMER", m.group(0), key=key), chunk)
            out.append(chunk)
        return "\n".join(out)

    @staticmethod
    def _collect_header_names(text):
        names = {}
        for m in HEADER.finditer(text):
            name = m.group("name").strip()
            if len(name) >= 3 and m.group("id") not in names:
                names[m.group("id")] = name
        return names

    @staticmethod
    def _name_patterns(names):
        pats = []
        for uid, name in names.items():          # full names, case-insensitive
            pats.append((len(name), re.compile(r"(?i)(?<!\w)" + re.escape(name) + r"(?!\w)"), uid))
        for uid, name in names.items():          # first names, case-sensitive
            first = name.split()[0]
            if first != name and len(first) >= 3 and first.lower() not in NAME_STOP:
                pats.append((len(first) - 1000, re.compile(r"(?<!\w)" + re.escape(first) + r"(?!\w)"), uid))
        pats.sort(key=lambda t: -t[0])           # longest first
        return [(rx, uid) for _, rx, uid in pats]


# ---------------------------------------------------------------- review file

def write_review(path, before, after, sample_size=60):
    b_lines, a_lines = before.split("\n"), after.split("\n")
    changed = [(b, a) for b, a in zip(b_lines, a_lines) if b != a]
    random.seed(42)
    sample = random.sample(changed, min(sample_size, len(changed)))

    leftovers = []
    for n, line in enumerate(a_lines, 1):
        for label, rx in LEFTOVER_CHECKS:
            if rx.search(line):
                leftovers.append((n, label, line))
                break

    with open(path, "w", encoding="utf-8") as f:
        f.write("KEEP THIS FILE PRIVATE - it contains original values.\n\n")
        f.write(f"=== {len(changed)} lines changed. Random sample (BEFORE / AFTER) ===\n\n")
        for b, a in sample:
            f.write(f"BEFORE: {b}\nAFTER : {a}\n\n")
        f.write(f"\n=== {len(leftovers)} lines that MAY still contain personal data - check these ===\n\n")
        for n, label, line in leftovers[:500]:
            f.write(f"line {n} [{label}]: {line}\n")
    return len(changed), len(leftovers)


# ---------------------------------------------------------------- self-test

SELFTEST_INPUT = """\
> Alice Kumar [U05Q8BKMNLQ] @ 15/10/2026 10:22:33 Z:
Customer-reported: CSV export fails for large date ranges
Reported by: Priya Sharma
contact john1234567@acme.com or call +1 (415) 555-1234 / 98765 43210
token xoxb-1234567890-abcdefghijkl and password: hunter2!
thread https://acme.slack.com/archives/C01ABCDEF/p1712345678123456?thread_ts=1712345678.123456
help link https://help.example.io/t?record_id=Rec0BJP0E8U23
card 4111 1111 1111 1111, PAN ABCDE1234F, server 10.0.12.7 timed out
|   > Bob Lee [U0ABCD1234] @ 15/10/2026 11:00:00 Z:
|   Thanks Alice, <@U05Q8BKMNLQ> fixed in commit a1234567b on localhost:3000, version 4.2.1
|   ts 1712345678.123456, order 88812345, UNAUTHORIZED error, user-facing bug
"""

# Slack List / workflow record layout (label on one line, value on the next).
SELFTEST_INPUT += """\
>  [] @ 15/04/2026 10:44:26 Z:
Reported by — *<@U05HK0MNFU569>*
Issue ID and URL: (Rec0AZZL678068)
> <https://examplecorp.slack.com/lists/T01BNSM9087/F08H066TRNC?record_id=Rec00AASZL678123>
*Customer*
Acme Widgets

*Details*
Could you help create an admin account for this email <mailto:skarale@widgets.example|skarale@widgets.example>? The customer uses Outlook today.

*Logrocket URL*

>  [] @ 16/04/2026 09:00:00 Z:
*Customer*
*Details*
Second report from acme widgets: SSO login loops after password reset
*Company*: Initech Systems
*Client*
Globex Ltd
>  [] @ 17/04/2026 12:00:00 Z:
Issue ID and URL: (Rec0ASZL12345)
*Customer*
Umbrella Technologies Pvt Ltd

*Details*
can u remove assignment rules from umbrella technologies when RH does this? UMBRELLA admins asked twice.
|   > Dana Fox [U02KLM7788] @ 17/04/2026 12:30:00 Z:
|   Checked Umbrella's workspace, rules are stale
"""

# Same customer mentioned in a LATER issue that has no Customer field of its own.
SCOPE_TEST_INPUT = """\
>  [] @ 18/04/2026 09:00:00 Z:
*Customer*
Hooli
*Details*
login fails for hooli admins
>  [] @ 19/04/2026 09:00:00 Z:
*Customer*

*Details*
same issue as Hooli last week
"""

EDGE_TEST_INPUT = """\
>  [] @ 15/04/2026 10:44:26 Z:
*Details*
export broken, set WORKFLOW2026 and UTF8ENCODING flags
*Customer*

>  [] @ 16/04/2026 09:00:00 Z:
*Customer*
|
|   > Dana Fox [U02KLM7788] @ 17/04/2026 12:30:00 Z:
|   bare id U02KLM7788 here
"""

SELFTEST_MUST_NOT_CONTAIN = [
    "Alice", "Kumar", "Priya", "Bob Lee", "U05Q8BKMNLQ", "U0ABCD1234", "acme.com", "john",
    "555-1234", "98765", "xoxb", "hunter2", "slack.com", "4111", "ABCDE1234F", "10.0.12.7",
    "U05HK0MNFU569", "examplecorp", "T01BNSM9087", "Acme Widgets", "skarale", "Initech", "Globex",
    "Umbrella", "Dana",
]
SELFTEST_MUST_CONTAIN = [
    "Customer-reported: CSV export fails for large date ranges",
    "Rec0BJP0E8U23", "a1234567b", "localhost:3000", "version 4.2.1",
    "1712345678.123456", "order 88812345", "UNAUTHORIZED", "user-facing bug",
    "(Rec0AZZL678068)", "?record_id=Rec00AASZL678123", "\nCUSTOMER_001\n\n*Details*",
    "*Details*\nCould you help create an admin account", "*Logrocket URL*",
    "*Customer*\n*Details*\n",                         # empty customer field left alone
    "SSO login loops after password reset", "*Company*: CUSTOMER_", "*Client*\nCUSTOMER_",
    "(Rec0ASZL12345)", "remove assignment rules from CUSTOMER_004 when RH does this? CUSTOMER_004 admins",
    "Checked CUSTOMER_004's workspace", "*Customer*\nCUSTOMER_004\n",
    "15/04/2026 10:44:26 Z", "17/04/2026 12:30:00 Z",              # timestamps kept
]


def selftest():
    r = Redactor(terms=[re.compile(r"(?i)(?<!\w)acme widgets(?!\w)")])
    out = r.redact(SELFTEST_INPUT)
    print(out)
    fails = [s for s in SELFTEST_MUST_NOT_CONTAIN if s.lower() in out.lower()]
    fails += [f"(missing) {s!r}" for s in SELFTEST_MUST_CONTAIN if s not in out]
    if out.count("\n") != SELFTEST_INPUT.count("\n"):
        fails.append("(line count changed)")
    if out.count("CUSTOMER_001") != 2:
        fails.append("(same customer did not get the same placeholder twice)")

    # customer scope: 'record' only touches the issue the name came from, 'file' touches everything
    rec = Redactor().redact(SCOPE_TEST_INPUT)
    fil = Redactor(customer_scope="file").redact(SCOPE_TEST_INPUT)
    print("\n--- scope=record ---\n" + rec + "--- scope=file ---\n" + fil)
    if "login fails for CUSTOMER_001 admins" not in rec or "same issue as Hooli last week" not in rec:
        fails.append("(scope=record did not behave as expected)")
    if "hooli" in fil.lower() or "same issue as CUSTOMER_001 last week" not in fil:
        fails.append("(scope=file did not behave as expected)")

    # regression checks for bugs fixed earlier
    edge = Redactor().redact(EDGE_TEST_INPUT)
    print("\n--- edge cases ---\n" + edge)
    for must in (">  [] @ 16/04/2026 09:00:00 Z:",                 # empty *Customer* before next message
                 "|   > USER_001 [USER_001] @ 17/04/2026 12:30:00 Z:",  # empty *Customer* before a reply
                 "set WORKFLOW2026 and UTF8ENCODING flags",          # not Slack IDs
                 "bare id USER_001 here"):                           # known ID without <@...>
        if must not in edge:
            fails.append(f"(edge case) missing {must!r}")
    if "CUSTOMER_" in edge or "U02KLM7788" in edge:
        fails.append("(edge case) header taken as a customer, or user ID left in")

    # regex: terms -> HIDDEN_nnn (never CUSTOMER_nnn), same link -> same placeholder
    hid = Redactor(terms=[(re.compile(r"https?://www\.loom\.com/share/[0-9a-f]+"), "HIDDEN")]).redact(
        "see https://www.loom.com/share/abc123 and again https://www.loom.com/share/abc123\n")
    if hid != "see HIDDEN_001 and again HIDDEN_001\n":
        fails.append(f"(regex terms) expected HIDDEN_001 twice, got {hid!r}")
    if fails:
        print("\nSELFTEST FAILED:", fails)
        sys.exit(1)
    print("\nSELFTEST PASSED")


# ---------------------------------------------------------------- main

# Project layout - paths are relative to the project folder (the parent of src/), so the
# script works the same no matter which folder you run it from.
PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_INPUT = os.path.join(PROJECT_DIR, "data", "raw", "customer-bugs.txt")
INTERIM_DIR = os.path.join(PROJECT_DIR, "data", "interim")    # draft - may still contain names
PRIVATE_DIR = os.path.join(PROJECT_DIR, "data", "private")    # NEVER share
DEFAULT_TERMS = os.path.join(PROJECT_DIR, "config", "terms.txt")


def rel(path):
    """Path as shown on screen: relative to the project folder."""
    try:
        return os.path.relpath(path, PROJECT_DIR)
    except ValueError:                       # e.g. a different drive on Windows
        return os.path.abspath(path)


def main():
    ap = argparse.ArgumentParser(description="Redact personal data from a slackdump .txt export, locally.")
    ap.add_argument("input", nargs="?", default=DEFAULT_INPUT,
                    help=f"your slackdump .txt file (default: {rel(DEFAULT_INPUT)})")
    ap.add_argument("--terms", default=None,
                    help=f"file with customer names / account IDs to hide (default: {rel(DEFAULT_TERMS)} if it exists)")
    ap.add_argument("--customer-scope", choices=["record", "file"], default="record",
                    help="where to search for a customer name learned from a *Customer* field: "
                         "'record' = only that issue (default), 'file' = the whole file")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if not os.path.isfile(args.input):
        ap.error(f"input file not found: {os.path.abspath(args.input)}\n"
                 f"Put your slackdump export at {rel(DEFAULT_INPUT)}")

    terms_path = args.terms or (DEFAULT_TERMS if os.path.isfile(DEFAULT_TERMS) else None)
    if terms_path and not os.path.isfile(terms_path):
        ap.error(f"terms file not found: {os.path.abspath(terms_path)}")

    # Outputs: draft -> data/interim/,  mapping + review -> data/private/
    # (data/final/ is written only by src/finalize.py, after review.)
    name = os.path.splitext(os.path.basename(args.input))[0]
    os.makedirs(INTERIM_DIR, exist_ok=True)
    os.makedirs(PRIVATE_DIR, exist_ok=True)
    out_path = os.path.join(INTERIM_DIR, name + ".draft.txt")
    mapping_path = os.path.join(PRIVATE_DIR, name + ".mapping.csv")
    review_path = os.path.join(PRIVATE_DIR, name + ".review.txt")
    if os.path.abspath(out_path) == os.path.abspath(args.input):
        ap.error("output would overwrite your input file")

    with open(args.input, encoding="utf-8", errors="replace") as f:
        original = f.read()

    terms = load_terms(terms_path) if terms_path else []
    r = Redactor(terms=terms, customer_scope=args.customer_scope)
    cleaned = r.redact(original)

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(cleaned)
    r.p.write_mapping(mapping_path)
    changed, leftovers = write_review(review_path, original, cleaned)

    # Summary only - never prints personal data to the screen.
    print(f"Input        : {rel(args.input)}")
    print(f"Terms        : {rel(terms_path) if terms_path else 'none'}")
    print(f"Draft        : {rel(out_path)}    (not final - review, then run src/finalize.py)")
    print(f"Mapping      : {rel(mapping_path)}   (KEEP PRIVATE)")
    print(f"Review       : {rel(review_path)}    (KEEP PRIVATE)")
    print(f"Lines changed: {changed}")
    print("Replacements :", ", ".join(f"{k}={v}" for k, v in sorted(r.p.hits.items())) or "none")
    print(f"Customer names learned from *Customer*-type fields: {len(r.learned_customers)}"
          f"  (searched per {'issue' if args.customer_scope == 'record' else 'whole file'})")
    print(f"Possible leftovers to check by hand: {leftovers}")


if __name__ == "__main__":
    main()