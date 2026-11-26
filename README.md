# Phishing Email Analyzer

![tests](https://github.com/clint-caccia/phishing-email-analyzer/actions/workflows/tests.yml/badge.svg)

A Python command line tool that reads raw `.eml` files, the way a SOC analyst gets them when someone hits "Report phishing", and checks them for red flags. It gives each email a 0 to 100 risk score and a verdict, maps the findings to MITRE ATT&CK, and pulls out the indicators of compromise (IOCs) so they can be blocked or searched for in other mailboxes.

No outside libraries. It only uses Python's built-in `email` package.

## What it checks

| Check | What it catches | Points |
|---|---|---|
| Email authentication | DMARC fail, SPF fail or softfail, DKIM fail, from the `Authentication-Results` header | 25 / 15 / 10 |
| Sender mismatch | Reply-To or Return-Path on a different domain than From | 15 / 5 |
| Display name tricks | A brand name or a fake address in the display name, or a "CEO" writing from Gmail | 15 each |
| Lookalike domains | Domains like `micros0ft-account` or `paypa1` that imitate a brand, caught with character swaps (0→o, 1→l, rn→m) and edit distance | 25 sender / 20 link |
| Link tricks | Link text that shows one site but goes to another, links to raw IPs, URL shorteners, punycode | 10-20 |
| Attachments | Executables, HTML files, macro documents, archives, and double extensions like `invoice.pdf.html` | 10-30 |
| Language | Pressure phrases ("within 24 hours", "suspended") and asks for passwords, payment or gift cards | 10 / 10 |

| Score | Verdict |
|---|---|
| 60-100 | LIKELY PHISHING |
| 30-59 | SUSPICIOUS |
| 0-29 | LIKELY SAFE |

## Quick start

```bash
git clone https://github.com/clint-caccia/phishing-email-analyzer.git
cd phishing-email-analyzer

python analyze_email.py samples/
python analyze_email.py samples/ --json results.json --iocs iocs.csv
```

Most mail clients can save a message as `.eml` (Outlook: File > Save As, Gmail: More > Download message).

## Sample output

Four made-up emails are in `samples/` ([full output](docs/sample_output.txt)):

```
SUMMARY
  100  LIKELY PHISHING  02_credential_phish.eml
  100  LIKELY PHISHING  03_invoice_attachment.eml
   35  SUSPICIOUS       04_bec_gift_cards.eml
    0  LIKELY SAFE      01_legit_newsletter.eml
```

The credential phish in detail:

```
Risk score: 100/100   Verdict: LIKELY PHISHING
+25  DMARC failed
+25  Lookalike sender domain  [T1684.001 Impersonation]
     micros0ft-account.example looks like microsoft but isn't one of its real domains.
+20  Link text doesn't match target  [T1566.002 Spearphishing Link]
     Text shows 'https://login.microsoftonline.com' but the link goes to micros0ft-account.example.
+15  Reply-To mismatch  [T1684.001 Impersonation]
     Replies go to support-desk@mailbox-helpdesk.example, not the sender's domain.
...
```

### The gift card email is the interesting one

Sample 4 is a business email compromise (BEC) message where a fake "CEO" asks the office manager to buy gift cards. It **passes SPF, DKIM and DMARC** because it really was sent from Gmail. Authentication only proves which domain sent a message, not that the sender is who they claim to be. The tool still flags it as Suspicious because an executive is writing from a free email account and asking for gift cards with urgency. It has no links or attachments for a scanner to catch, which is why BEC gets through so often.

## IOC export

`--iocs` writes a CSV of indicators from every email that scored Suspicious or worse:

| type | example |
|---|---|
| sender_email / sender_domain | `no-reply@micros0ft-account.example` |
| reply_to | `support-desk@mailbox-helpdesk.example` |
| url / domain | `http://micros0ft-account.example/login?u=frontdesk` |
| received_ip | `203.0.113.66` |
| attachment_sha256 | SHA-256 hash of each attachment, for checking against threat intel like VirusTotal |

Emails that scored Likely Safe are left out so a legitimate sender doesn't get blocked by accident.

## How it works

1. **Parse** (`phish_analyzer/parse.py`). Python's `email` package reads the headers and walks every MIME part. Plain text and HTML bodies are kept, attachments are hashed with SHA-256, and an HTML parser collects every `<a href>` along with the text a reader actually sees.
2. **Check** (`phish_analyzer/checks.py`). Each check is a small function that returns findings with points. The lookalike check strips common character swaps out of a domain and then looks for a brand name inside it or a brand one edit away, skipping the brand's real domains.
3. **Report** (`phish_analyzer/report.py`). Prints the findings in order of weight, adds up the score (capped at 100), lists ATT&CK techniques, and optionally writes JSON and an IOC CSV.

The script exits with code `2` if any email is Likely Phishing, so it can feed an automated workflow.

## Project layout

```
phishing-email-analyzer/
├── analyze_email.py         # command line entry point
├── phish_analyzer/
│   ├── parse.py             # .eml -> ParsedEmail
│   ├── checks.py            # the checks and the scoring
│   └── report.py            # text report, JSON, IOC CSV
├── samples/
│   ├── make_samples.py      # builds the sample emails
│   └── *.eml
├── tests/
└── docs/sample_output.txt
```

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest -v
```

The tests run every sample end to end and check the lookalike detection, attachment rules, score cap and IOC extraction. GitHub Actions runs them on every push.

## Limitations

- Brand matching is a substring check, so a real company with a brand inside its name (an "applebees" domain contains "apple") would be a false positive. A real deployment would use an allowlist.
- It trusts the `Authentication-Results` header written by the receiving mail server and doesn't do its own DNS lookups.
- Keyword checks are English only and easy to get around with different wording.
- `registered_domain` just takes the last two labels, so domains like `example.co.uk` aren't handled right. The `tldextract` library would fix that.
- It doesn't open attachments or visit links. Hashes and URLs go in the IOC export for a sandbox or VirusTotal to look at.

## About the samples

Everything in `samples/` is fake. Domains use the reserved `.example` top-level domain, IPs come from the documentation ranges, and the "malicious" attachment is a one-line placeholder.

## Related projects

- [auth-log-analyzer](https://github.com/clint-caccia/auth-log-analyzer): flags brute force and suspicious logins in Linux auth logs. If a phish like sample 2 worked, this is where the stolen password would show up next.
- [nist-csf-risk-assessment](https://github.com/clint-caccia/nist-csf-risk-assessment): email account takeover (R02) is one of its top risks, and PR.AT awareness training is one of its top gaps.

## Author

**Clint Caccia**, Computer Information Systems, James Madison University
[LinkedIn](https://www.linkedin.com/in/clint-caccia-b70428354) · [GitHub](https://github.com/clint-caccia)
