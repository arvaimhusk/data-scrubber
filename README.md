# bug-intel

Local tools to clean a Slack export of customer-raised bugs before analysis.
Python 3.8+, standard library only. Nothing is sent anywhere; no AI is involved.

## Folder layout

```
bug-intel/
├── README.md
├── .gitignore
├── src/                                 code
│   ├── redact_slack.py                  step 1: removes personal data -> draft
│   ├── summarize_review.py              step 2: groups what is left into a checklist
│   └── finalize.py                      step 3: approves the draft -> final
├── config/                              your decisions (keep - they are the audit trail)
│   ├── terms.txt                        names / IDs to HIDE
│   └── allow.txt                        checked items that are HARMLESS
├── data/
│   ├── raw/        PRIVATE              original slackdump export, never modified
│   │   └── customer-bugs.txt
│   ├── interim/    PRIVATE              draft, overwritten on every run, may still have names
│   │   └── customer-bugs.draft.txt
│   ├── final/      SHAREABLE            written ONLY by finalize.py, after review
│   │   ├── customer-bugs.final.txt
│   │   └── customer-bugs.approval.txt   when / how it was approved (counts only)
│   └── private/    PRIVATE              never share or upload
│       ├── customer-bugs.mapping.csv    placeholder -> real value
│       ├── customer-bugs.review.txt     before/after samples + possible leftovers
│       └── customer-bugs.summary.txt    grouped checklist
└── docs/
    └── customer-bug-intelligence-plan.md
```

**Rule: only `data/final/` ever leaves your machine.**

## Run

From the `bug-intel` folder:

```bash
python3 src/redact_slack.py --selftest          # once: last line must be SELFTEST PASSED

python3 src/redact_slack.py --customer-scope file   # 1. raw -> draft
python3 src/summarize_review.py                     # 2. checklist
open data/private/customer-bugs.summary.txt         #    (macOS)
#   ...update config/terms.txt and config/allow.txt, repeat 1-2 until clean...
python3 src/finalize.py                             # 3. draft -> final
```

`config/terms.txt` and `config/allow.txt` are picked up automatically.

## Review loop

Every `[CHECK]` group in the summary ends with two ready-made lines. Decide once per
group and copy **one** of them - never copy the `e.g.` examples:

```
[        CHECK]     8 x  Link: www.loom.com
                e.g. https://www.loom.com/share/497d...
                harmless?  add to config/allow.txt :  group:Link: www.loom.com
                sensitive? add to config/terms.txt :  regex:(?:https?://)?www\.loom\.com[/?#:][^\s>|]*
```

| It is...                              | Copy the line for  | Then re-run       |
|---------------------------------------|--------------------|-------------------|
| sensitive (person, customer, share link, phone) | `config/terms.txt` | steps 1 and 2     |
| harmless (Team, internal ID behind a login)     | `config/allow.txt` | step 2            |

Links are grouped by website, so one line covers e.g. every Loom link.
`probably safe` groups need nothing - they never block `finalize.py`.

`terms.txt` changes the data (used by step 1). `allow.txt` only shortens the
checklist (used by step 2) - it never changes the data.

Both files take one item per line; `regex:` lines are patterns, `#` lines are comments.
`allow.txt` also accepts `group:<group name>` (exactly as the summary prints it) to allow a whole group.

**Shortcut for harmless groups:** paste any one `e.g.` line of a CHECK group into `allow.txt`.
It allows that item **and its whole group** (same website, or same number format), now and in
future runs. The top of the summary lists every group learned this way, with the `allow.txt`
line it came from - delete that line to undo it.
This works for `allow.txt` only. To hide something, always use the group's ready-made
`terms.txt` line.

## Finalize

`finalize.py` copies the draft to `data/final/` **only if**:

- no CHECK groups are left (or you pass `--override` after deciding the rest are fine), and
- the draft is newer than `config/terms.txt` and the raw export (so your latest terms are applied).

It also writes `customer-bugs.approval.txt`: date, override yes/no, file checksum and
placeholder counts. It contains no personal data and can travel with the final file.

## Placeholders in the cleaned data

| Placeholder          | Was                                            |
|----------------------|------------------------------------------------|
| `CUSTOMER_001`       | customer / company / account name              |
| `HIDDEN_001`         | anything hidden by a `regex:` line in `config/terms.txt` (links, numbers) |
| `USER_001`           | person who posted, or a `<@U...>` mention      |
| `EMAIL_001`          | email address                                  |
| `PHONE_001`          | phone number                                   |
| `[NAME]`             | value of a person field (Reported by, ...)     |
| `[SECRET]`           | token, API key, password                       |
| `[SLACK_LINK]`       | Slack link (the `?record_id=...` part is kept) |
| `[CARD]` `[PAN]` `[AADHAAR]` `[IP]` | as named                        |

The same real value always gets the same placeholder, so counts still work.
Kept on purpose: issue / record IDs (`Rec...`), timestamps, commit hashes, versions.