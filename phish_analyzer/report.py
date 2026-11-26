"""Turn the results into a terminal report, an IOC list, and JSON."""

import csv
import json
import re
from dataclasses import asdict
from urllib.parse import urlparse

from .checks import registered_domain, score, verdict
from .parse import domain_of

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def extract_iocs(e):
    """Indicators of compromise an analyst would block or search for in other mailboxes."""
    iocs = []
    iocs.append(("sender_email", e.from_addr))
    iocs.append(("sender_domain", domain_of(e.from_addr)))
    if e.reply_to:
        iocs.append(("reply_to", e.reply_to))
    for link in e.links:
        iocs.append(("url", link.href))
        host = (urlparse(link.href).hostname or "").lower()
        if host:
            iocs.append(("domain", host))
    for hop in e.received:
        for ip in IP_RE.findall(hop):
            if not ip.startswith(("10.", "192.168.", "127.")):
                iocs.append(("received_ip", ip))
    for att in e.attachments:
        iocs.append(("attachment_sha256", f"{att.sha256}  {att.filename}"))
    seen, unique = set(), []
    for kind, value in iocs:
        if (kind, value) not in seen:
            seen.add((kind, value))
            unique.append((kind, value))
    return unique


def text_report(path, e, findings):
    points = score(findings)
    lines = ["=" * 64, f"File:     {path}", f"Subject:  {e.subject}",
             f"From:     {e.from_name} <{e.from_addr}>"]
    if e.reply_to:
        lines.append(f"Reply-To: {e.reply_to}")
    lines.append(f"Links: {len(e.links)}   Attachments: {len(e.attachments)}")
    lines.append("-" * 64)
    lines.append(f"Risk score: {points}/100   Verdict: {verdict(points)}")
    lines.append("-" * 64)
    for f in findings:
        tag = f"  [{f.attack}]" if f.attack else ""
        lines.append(f"+{f.points:<3} {f.check}{tag}")
        lines.append(f"     {f.detail}")
    if not findings:
        lines.append("No red flags found.")
    techniques = sorted({f.attack for f in findings if f.attack})
    if techniques:
        lines.append("")
        lines.append("ATT&CK: " + "; ".join(techniques))
    return "\n".join(lines)


def to_dict(path, e, findings):
    points = score(findings)
    return {
        "file": path,
        "subject": e.subject,
        "from": e.from_addr,
        "score": points,
        "verdict": verdict(points),
        "findings": [asdict(f) for f in findings],
        "iocs": [{"type": k, "value": v} for k, v in extract_iocs(e)],
    }


def write_json(results, path):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2)


def write_iocs_csv(results, path):
    """Only emails that scored Suspicious or worse, so nobody blocks a legit sender by accident."""
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["source_file", "verdict", "type", "value"])
        for r in results:
            if r["verdict"] == "LIKELY SAFE":
                continue
            for ioc in r["iocs"]:
                writer.writerow([r["file"], r["verdict"], ioc["type"], ioc["value"]])
