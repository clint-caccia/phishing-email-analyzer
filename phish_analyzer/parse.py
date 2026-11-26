"""Read a raw .eml file and pull out the parts the checks need."""

import hashlib
import re
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from typing import List, Optional, Tuple

URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)


@dataclass
class Link:
    href: str
    text: str = ""  # visible text in HTML, empty for plain text links


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str


@dataclass
class ParsedEmail:
    subject: str
    from_name: str
    from_addr: str
    reply_to: Optional[str]
    return_path: Optional[str]
    to: List[str]
    date: str
    auth_results: str
    received: List[str]
    text: str
    links: List[Link] = field(default_factory=list)
    attachments: List[Attachment] = field(default_factory=list)


class _LinkCollector(HTMLParser):
    """Collect <a href> targets together with the text a reader actually sees."""

    def __init__(self):
        super().__init__()
        self.links: List[Link] = []
        self._href = None
        self._text = []
        self.plain = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_endtag(self, tag):
        if tag == "a" and self._href:
            self.links.append(Link(self._href.strip(), "".join(self._text).strip()))
            self._href = None

    def handle_data(self, data):
        self.plain.append(data)
        if self._href is not None:
            self._text.append(data)


def domain_of(address: str) -> str:
    return address.rsplit("@", 1)[-1].lower().strip(">").strip() if "@" in address else ""


def _addr(header_value) -> Optional[str]:
    if not header_value:
        return None
    return parseaddr(str(header_value))[1].lower() or None


def parse_eml(path: str) -> ParsedEmail:
    with open(path, "rb") as handle:
        msg = BytesParser(policy=policy.default).parse(handle)

    from_name, from_addr = parseaddr(str(msg.get("From", "")))
    text_parts, html_parts, attachments = [], [], []

    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        disposition = part.get_content_disposition()
        if filename or disposition == "attachment":
            payload = part.get_payload(decode=True) or b""
            attachments.append(
                Attachment(
                    filename=filename or "(no name)",
                    content_type=part.get_content_type(),
                    size=len(payload),
                    sha256=hashlib.sha256(payload).hexdigest(),
                )
            )
        elif part.get_content_type() == "text/plain":
            text_parts.append(part.get_content())
        elif part.get_content_type() == "text/html":
            html_parts.append(part.get_content())

    links: List[Link] = []
    visible = list(text_parts)
    for html in html_parts:
        collector = _LinkCollector()
        collector.feed(html)
        links.extend(collector.links)
        visible.append(" ".join(collector.plain))
    seen = {l.href for l in links}
    for text in text_parts:
        for url in URL_RE.findall(text):
            if url not in seen:
                links.append(Link(url))
                seen.add(url)

    return ParsedEmail(
        subject=str(msg.get("Subject", "")),
        from_name=from_name,
        from_addr=from_addr.lower(),
        reply_to=_addr(msg.get("Reply-To")),
        return_path=_addr(msg.get("Return-Path")),
        to=[a for _, a in getaddresses([str(v) for v in msg.get_all("To", [])])],
        date=str(msg.get("Date", "")),
        auth_results=" ".join(str(v) for v in msg.get_all("Authentication-Results", [])),
        received=[str(v) for v in msg.get_all("Received", [])],
        text="\n".join(visible),
        links=links,
        attachments=attachments,
    )


def auth_result(auth_results: str, mechanism: str) -> Tuple[str, str]:
    """Return (result, raw) for spf/dkim/dmarc from the Authentication-Results header."""
    found = re.search(rf"\b{mechanism}=(\w+)", auth_results, re.IGNORECASE)
    return (found.group(1).lower() if found else "none", auth_results)
