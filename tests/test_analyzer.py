import os

from phish_analyzer.checks import (
    check_attachments,
    lookalike_brand,
    run_checks,
    score,
    verdict,
)
from phish_analyzer.parse import Attachment, ParsedEmail, parse_eml
from phish_analyzer.report import extract_iocs

SAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples")


def analyze(name):
    e = parse_eml(os.path.join(SAMPLES, name))
    findings = run_checks(e)
    return e, findings, score(findings)


def checks_hit(findings):
    return {f.check for f in findings}


# ---- whole samples


def test_legit_newsletter_is_safe():
    _, findings, points = analyze("01_legit_newsletter.eml")
    assert verdict(points) == "LIKELY SAFE"
    assert findings == []


def test_credential_phish_is_caught():
    _, findings, points = analyze("02_credential_phish.eml")
    assert verdict(points) == "LIKELY PHISHING"
    hit = checks_hit(findings)
    assert {"DMARC failed", "Lookalike sender domain", "Link text doesn't match target", "Reply-To mismatch"} <= hit


def test_invoice_attachment_is_caught():
    _, findings, points = analyze("03_invoice_attachment.eml")
    assert verdict(points) == "LIKELY PHISHING"
    assert {"HTML attachment", "Double extension", "URL shortener", "Link to raw IP address"} <= checks_hit(findings)


def test_bec_is_flagged_even_though_auth_passes():
    _, findings, points = analyze("04_bec_gift_cards.eml")
    assert verdict(points) == "SUSPICIOUS"
    assert "Executive on free email" in checks_hit(findings)
    assert "DMARC failed" not in checks_hit(findings)


# ---- individual pieces


def test_lookalike_brand():
    assert lookalike_brand("micros0ft-account.example") == "microsoft"
    assert lookalike_brand("paypa1.example") == "paypal"
    assert lookalike_brand("login.docusign-secure.example") == "docusign"
    assert lookalike_brand("microsoft.com") is None
    assert lookalike_brand("mail.paypal.com") is None
    assert lookalike_brand("blueridgedental.example") is None


def test_attachment_rules():
    def email_with(name):
        return ParsedEmail("", "", "a@b.example", None, None, [], "", "", [], "",
                           attachments=[Attachment(name, "application/octet-stream", 1, "x")])

    assert "Executable attachment" in checks_hit(check_attachments(email_with("update.exe")))
    assert "Double extension" in checks_hit(check_attachments(email_with("resume.pdf.exe")))
    assert "Macro-enabled document" in checks_hit(check_attachments(email_with("payroll.xlsm")))
    assert check_attachments(email_with("agenda.pdf")) == []


def test_score_caps_at_100():
    _, findings, points = analyze("03_invoice_attachment.eml")
    assert sum(f.points for f in findings) > 100
    assert points == 100


def test_iocs_include_attachment_hash_and_urls():
    e, _, _ = analyze("03_invoice_attachment.eml")
    kinds = {k for k, _ in extract_iocs(e)}
    assert {"sender_domain", "url", "attachment_sha256", "received_ip"} <= kinds
