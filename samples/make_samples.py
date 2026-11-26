#!/usr/bin/env python3
"""Build the sample .eml files.

All of these are made up. Domains use the reserved .example top-level domain
and IPs come from the documentation ranges, so nothing here points at a real
system. The 'malicious' attachment is a few lines of harmless placeholder text.
"""

import os
from email.message import EmailMessage

HERE = os.path.dirname(os.path.abspath(__file__))


def save(msg, name):
    with open(os.path.join(HERE, name), "wb") as handle:
        handle.write(bytes(msg))
    print("wrote", name)


def base(subject, from_, to, auth, received_ip, date):
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_
    msg["To"] = to
    msg["Date"] = date
    msg["Received"] = f"from mail.sender.example ([{received_ip}]) by mx.blueridgedental.example; {date}"
    msg["Authentication-Results"] = f"mx.blueridgedental.example; {auth}"
    return msg


# 1. A normal internal newsletter. Should come out LIKELY SAFE.
m = base("November staff newsletter", "Blue Ridge Family Dental <updates@blueridgedental.example>",
         "staff@blueridgedental.example", "spf=pass dkim=pass dmarc=pass", "192.0.2.10",
         "Mon, 16 Nov 2026 09:00:00 -0500")
m["Return-Path"] = "<updates@blueridgedental.example>"
m.set_content("Hi team,\n\nThe holiday schedule is posted on the portal: https://portal.blueridgedental.example/schedule\n\nThanks,\nOffice Manager")
m.add_alternative(
    "<p>Hi team,</p><p>The holiday schedule is posted on the "
    "<a href='https://portal.blueridgedental.example/schedule'>staff portal</a>.</p><p>Thanks,<br>Office Manager</p>",
    subtype="html")
save(m, "01_legit_newsletter.eml")

# 2. Credential phishing pretending to be Microsoft 365.
m = base("Action required: unusual sign-in activity on your account",
         "Microsoft 365 Security <no-reply@micros0ft-account.example>",
         "frontdesk@blueridgedental.example", "spf=softfail dkim=none dmarc=fail", "203.0.113.66",
         "Tue, 17 Nov 2026 02:14:00 -0500")
m["Reply-To"] = "support-desk@mailbox-helpdesk.example"
m["Return-Path"] = "<bounce@bulk-sender.example>"
m.set_content("We detected unusual activity. Verify your account within 24 hours or it will be suspended.")
m.add_alternative(
    "<p>We detected <b>unusual activity</b> on your Microsoft 365 account.</p>"
    "<p>Verify your account within 24 hours or access will be suspended.</p>"
    "<p><a href='http://micros0ft-account.example/login?u=frontdesk'>https://login.microsoftonline.com</a></p>",
    subtype="html")
save(m, "02_credential_phish.eml")

# 3. Fake invoice with an HTML attachment (HTML smuggling style lure).
m = base("Invoice 4471 past due - final notice",
         "DocuSign <dse@docusign-secure.example>",
         "billing@blueridgedental.example", "spf=fail dkim=fail dmarc=fail", "198.51.100.140",
         "Wed, 18 Nov 2026 11:31:00 -0500")
m.set_content("Final notice. Invoice attached, please review and pay immediately.\n"
              "Backup link: https://bit.ly/3xExample\nMirror: http://198.51.100.140/inv/4471")
m.add_attachment(b"<html><!-- harmless placeholder for a fake login page --></html>",
                 maintype="text", subtype="html", filename="Invoice_4471.pdf.html")
save(m, "03_invoice_attachment.eml")

# 4. Business email compromise: fake owner asking for gift cards. No links at all.
m = base("Quick favor", "Dr. Ellen Hart CEO <ellen.hart.office@gmail.com>",
         "officemanager@blueridgedental.example", "spf=pass dkim=pass dmarc=pass", "192.0.2.200",
         "Thu, 19 Nov 2026 16:02:00 -0500")
m["Reply-To"] = "ellen.hart.office@gmail.com"
m.set_content("Are you at your desk? I need you to pick up 5 gift cards for a client appreciation thing "
              "right away. I'm in meetings all day so just email me the codes. I'll pay you back.\n\nEllen")
save(m, "04_bec_gift_cards.eml")
