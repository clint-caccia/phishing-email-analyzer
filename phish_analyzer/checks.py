"""Phishing checks. Each one looks at a ParsedEmail and returns zero or more Findings.

Every finding carries points. The points add up to a 0-100 risk score, so the
weights below are the main thing to tune.
"""

import ipaddress
import re
from dataclasses import dataclass
from typing import List
from urllib.parse import urlparse

from .parse import ParsedEmail, auth_result, domain_of

# Brands that get impersonated a lot, and the domains they really send from.
BRANDS = {
    "microsoft": {"microsoft.com", "office.com", "office365.com", "outlook.com", "live.com"},
    "paypal": {"paypal.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "amazon": {"amazon.com"},
    "apple": {"apple.com", "icloud.com"},
    "google": {"google.com", "gmail.com"},
    "netflix": {"netflix.com"},
    "adobe": {"adobe.com"},
    "dropbox": {"dropbox.com"},
    "linkedin": {"linkedin.com"},
    "fedex": {"fedex.com"},
    "usps": {"usps.com"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
}
FREEMAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "proton.me", "icloud.com"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly"}

# Characters attackers swap in to make a domain look like a brand.
HOMOGLYPHS = {"0": "o", "1": "l", "3": "e", "5": "s", "@": "a", "rn": "m", "vv": "w"}

DANGEROUS_EXT = {".exe", ".scr", ".js", ".jse", ".vbs", ".bat", ".cmd", ".ps1", ".hta", ".lnk", ".msi", ".iso", ".img", ".jar"}
MACRO_EXT = {".docm", ".xlsm", ".pptm", ".xlam"}
ARCHIVE_EXT = {".zip", ".rar", ".7z", ".gz"}
HTML_EXT = {".html", ".htm", ".shtml", ".svg"}

URGENCY = ["urgent", "immediately", "within 24 hours", "suspended", "final notice", "act now",
           "unusual activity", "will be closed", "expires today", "right away"]
ASKS = ["verify your account", "confirm your password", "update your payment", "login to",
        "sign in to", "gift card", "wire transfer", "bank details", "reset your password", "invoice attached"]
EXEC_WORDS = ["ceo", "president", "director", "cfo", "owner"]


@dataclass
class Finding:
    check: str
    points: int
    detail: str
    attack: str = ""


def registered_domain(host: str) -> str:
    """Rough 'example.com' from 'login.mail.example.com'. Good enough for these checks."""
    host = host.lower().strip(".")
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _deglyph(label: str) -> str:
    for fake, real in HOMOGLYPHS.items():
        label = label.replace(fake, real)
    return label


def lookalike_brand(domain: str):
    """Return the brand a domain is pretending to be, or None.

    Catches 'micros0ft-login.example' (homoglyph + brand inside a longer name)
    and 'paypa1.example' (one character off), but not the brand's real domains.
    """
    if not domain:
        return None
    reg = registered_domain(domain)
    label = reg.split(".")[0]
    clean = _deglyph(label)
    for brand, real_domains in BRANDS.items():
        if reg in real_domains:
            return None
        if brand in clean:
            return brand
        if len(brand) >= 5 and 0 < _levenshtein(clean, brand) <= 1:
            return brand
    return None


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


# ---------------------------------------------------------------- checks


def check_authentication(e: ParsedEmail) -> List[Finding]:
    out = []
    spf, _ = auth_result(e.auth_results, "spf")
    dkim, _ = auth_result(e.auth_results, "dkim")
    dmarc, _ = auth_result(e.auth_results, "dmarc")
    if dmarc == "fail":
        out.append(Finding("DMARC failed", 25, "The sending domain's DMARC policy says this message is not legitimately from it."))
    if spf in ("fail", "softfail"):
        out.append(Finding("SPF failed", 15, f"SPF result was '{spf}': the sending server isn't authorized for this domain."))
    if dkim == "fail":
        out.append(Finding("DKIM failed", 10, "The DKIM signature didn't verify, so the message may have been altered or forged."))
    if not e.auth_results:
        out.append(Finding("No authentication results", 5, "No Authentication-Results header to check SPF, DKIM or DMARC."))
    return out


def check_sender_mismatch(e: ParsedEmail) -> List[Finding]:
    out = []
    from_dom = domain_of(e.from_addr)
    if e.reply_to and domain_of(e.reply_to) != from_dom:
        out.append(Finding("Reply-To mismatch", 15,
                           f"Replies go to {e.reply_to}, not the sender's domain ({from_dom}).", "T1684.001 Impersonation"))
    if e.return_path and domain_of(e.return_path) != from_dom:
        out.append(Finding("Return-Path mismatch", 5,
                           f"Bounce address domain {domain_of(e.return_path)} differs from From domain {from_dom}."))
    return out


def check_display_name(e: ParsedEmail) -> List[Finding]:
    out = []
    name = e.from_name.lower()
    from_dom = domain_of(e.from_addr)
    embedded = re.search(r"[\w.+-]+@([\w-]+\.[\w.-]+)", name)
    if embedded and embedded.group(1) != from_dom:
        out.append(Finding("Fake address in display name", 15,
                           f"Display name shows '{embedded.group(0)}' but the real sender is {e.from_addr}.", "T1684.001 Impersonation"))
    for brand, real in BRANDS.items():
        if brand in name.replace(" ", "") and registered_domain(from_dom) not in real:
            out.append(Finding("Brand in display name", 15,
                               f"Display name says '{e.from_name}' but the mail comes from {from_dom}.", "T1684.001 Impersonation"))
            break
    if any(w in name.split() for w in EXEC_WORDS) and from_dom in FREEMAIL:
        out.append(Finding("Executive on free email", 15,
                           f"'{e.from_name}' is writing from a personal {from_dom} address, a common business email compromise move.",
                           "T1684.001 Impersonation"))
    return out


def check_lookalike_sender(e: ParsedEmail) -> List[Finding]:
    brand = lookalike_brand(domain_of(e.from_addr))
    if brand:
        return [Finding("Lookalike sender domain", 25,
                        f"{domain_of(e.from_addr)} looks like {brand} but isn't one of its real domains.", "T1684.001 Impersonation")]
    return []


def check_links(e: ParsedEmail) -> List[Finding]:
    out = []
    flagged_lookalike = False
    for link in e.links:
        host = _host(link.href)
        if not host:
            continue
        shown = re.search(r"(?:https?://)?([\w-]+(?:\.[\w-]+)+)", link.text or "")
        if shown and "." in shown.group(1) and registered_domain(shown.group(1)) != registered_domain(host):
            out.append(Finding("Link text doesn't match target", 20,
                               f"Text shows '{link.text}' but the link goes to {host}.", "T1566.002 Spearphishing Link"))
        try:
            ipaddress.ip_address(host)
            out.append(Finding("Link to raw IP address", 15, f"{link.href} points straight at an IP address.", "T1566.002 Spearphishing Link"))
        except ValueError:
            pass
        if registered_domain(host) in SHORTENERS:
            out.append(Finding("URL shortener", 10, f"{link.href} hides its real destination.", "T1566.002 Spearphishing Link"))
        if "xn--" in host:
            out.append(Finding("Punycode domain", 15, f"{host} uses punycode, which can hide lookalike characters.", "T1566.002 Spearphishing Link"))
        brand = lookalike_brand(host)
        if brand and not flagged_lookalike:
            out.append(Finding("Lookalike link domain", 20, f"{host} imitates {brand}.", "T1566.002 Spearphishing Link"))
            flagged_lookalike = True
    return out


def check_language(e: ParsedEmail) -> List[Finding]:
    body = f"{e.subject}\n{e.text}".lower()
    out = []
    urgent = [w for w in URGENCY if w in body]
    asks = [w for w in ASKS if w in body]
    if urgent:
        out.append(Finding("Urgent language", 10, "Pressure phrases: " + ", ".join(f"'{w}'" for w in urgent)))
    if asks:
        out.append(Finding("Asks for credentials or money", 10, "Requests: " + ", ".join(f"'{w}'" for w in asks)))
    return out


def check_attachments(e: ParsedEmail) -> List[Finding]:
    out = []
    for att in e.attachments:
        name = att.filename.lower()
        exts = re.findall(r"\.[a-z0-9]+", name)
        last = exts[-1] if exts else ""
        tag = "T1566.001 Spearphishing Attachment"
        if last in DANGEROUS_EXT:
            out.append(Finding("Executable attachment", 30, f"{att.filename} can run code when opened.", tag))
        if last in HTML_EXT:
            out.append(Finding("HTML attachment", 25, f"{att.filename} opens a local web page, often a fake login or HTML smuggling.", tag))
        if last in MACRO_EXT:
            out.append(Finding("Macro-enabled document", 20, f"{att.filename} can contain macros.", tag))
        if last in ARCHIVE_EXT:
            out.append(Finding("Archive attachment", 10, f"{att.filename} can hide files from email scanners.", tag))
        if len(exts) >= 2 and exts[-2] in {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt"} and last != exts[-2]:
            out.append(Finding("Double extension", 20, f"{att.filename} pretends to be a {exts[-2]} file.", tag))
    return out


ALL_CHECKS = [check_authentication, check_sender_mismatch, check_display_name,
              check_lookalike_sender, check_links, check_language, check_attachments]


def run_checks(e: ParsedEmail) -> List[Finding]:
    findings = []
    for check in ALL_CHECKS:
        findings.extend(check(e))
    return sorted(findings, key=lambda f: -f.points)


def score(findings: List[Finding]) -> int:
    return min(100, sum(f.points for f in findings))


def verdict(points: int) -> str:
    if points >= 60:
        return "LIKELY PHISHING"
    if points >= 30:
        return "SUSPICIOUS"
    return "LIKELY SAFE"
