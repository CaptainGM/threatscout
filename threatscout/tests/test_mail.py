import base64
from email.message import EmailMessage

import dkim
import pytest
from fastapi.testclient import TestClient

from threatscout import api, mail
from threatscout.models import IOCType

RECEIVED = [
    "Received: from mx.gmail.example (mx.gmail.example [209.85.220.41]) by mx.ours.example",
    "Received: from relay.example (relay.example [74.125.2.5]) by mx.gmail.example",
    "Received: from pc.local (pc.local [192.168.1.20]) by relay.example",
    "Received: from home.example (home.example [81.2.69.160]) by pc.local",
]


class FakeDns:
    # Gerçek DNS yerine sabit kayıtlar. Testler internete bağlı kalmasın diye kullanılıyor.
    def __init__(self, txt=None):
        self.records = txt or {}

    def txt(self, name):
        return list(self.records.get(name.lower().rstrip("."), []))

    def ptr(self, ip):
        return ""


@pytest.fixture
def spf_dns(monkeypatch):
    # pyspf kendi DNS fonksiyonunu kullanır. Testte onu bu sözlükteki kayıtlarla değiştiriyoruz.
    records = {}

    def lookup(name, qtype, strict=True, timeout=20):
        if qtype != "TXT":
            return []
        return [((name, qtype), (text.encode(),)) for text in records.get(name.lower(), [])]

    monkeypatch.setattr(mail.spf, "DNSLookup", lookup)
    return records


@pytest.fixture
def signed():
    # Test anahtarı her çalıştırmada yeniden üretilir, böylece depoya özel anahtar girmez
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    public = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )

    def make(body=b"Merhaba\r\n"):
        message = (
            b"From: Banka <guvenlik@banka.com.tr>\r\n"
            b"To: ben@example.org\r\n"
            b"Subject: Hesap guvenligi\r\n"
            b"Date: Tue, 20 Oct 2026 10:00:00 +0300\r\n"
            b"\r\n" + body
        )
        signature = dkim.sign(
            message, b"sel", b"banka.com.tr", pem, include_headers=[b"from", b"to", b"subject", b"date"]
        )
        return signature + message

    key_record = f"v=DKIM1; k=rsa; p={base64.b64encode(public).decode()}"
    return make, key_record


def raw_mail(*headers, sender="Banka <guvenlik@banka.com.tr>", body="Merhaba\n"):
    lines = [
        f"From: {sender}",
        "To: ben@example.org",
        "Subject: Hesap guvenligi",
        "Date: Tue, 20 Oct 2026 10:00:00 +0300",
        "Message-ID: <1@banka.com.tr>",
        *headers,
    ]
    return ("\n".join(lines) + "\n\n" + body).encode("utf-8")


def test_sender_and_subject_are_decoded():
    msg = EmailMessage()
    msg["From"] = '"Banka Destek" <destek@banka.com.tr>'
    msg["Subject"] = "Hesap güvenliği"
    msg.set_content("Merhaba")
    report = mail.analyze_mail(msg.as_bytes(), use_dns=False)
    assert report.subject == "Hesap güvenliği"
    assert report.from_name == "Banka Destek"
    assert report.sender == "destek@banka.com.tr"


def test_connecting_ip_is_the_newest_public_hop_and_origin_is_the_oldest():
    report = mail.analyze_mail(raw_mail(*RECEIVED), use_dns=False)
    assert report.connecting_ip == "209.85.220.41"
    assert report.origin_ip == "81.2.69.160"


def test_received_spf_client_ip_is_preferred():
    spf_header = "Received-SPF: pass (google.com: designates 74.125.2.5 as permitted sender) client-ip=74.125.2.5;"
    report = mail.analyze_mail(raw_mail(spf_header, *RECEIVED), use_dns=False)
    assert report.connecting_ip == "74.125.2.5"


def test_only_the_topmost_authentication_results_header_is_trusted():
    report = mail.analyze_mail(
        raw_mail(
            "Authentication-Results: mx.ours.example; spf=pass smtp.mailfrom=banka.com.tr; dkim=pass header.d=banka.com.tr; dmarc=pass",
            "Authentication-Results: evil.example; spf=fail; dkim=fail; dmarc=fail",
        ),
        use_dns=False,
    )
    assert report.receiver == {"spf": "pass", "dkim": "pass", "dmarc": "pass"}


def test_spf_checks_the_connecting_ip_for_the_sender_domain(spf_dns):
    spf_dns["banka.com.tr"] = ["v=spf1 ip4:209.85.220.0/24 -all"]
    assert mail.check_spf("209.85.220.41", "guvenlik@banka.com.tr") == "pass"
    assert mail.check_spf("1.2.3.4", "guvenlik@banka.com.tr") == "fail"
    assert mail.check_spf("1.2.3.4", "kimse@yok.example") == "none"


def test_org_domain_and_alignment():
    assert mail.org_domain("mail.banka.com.tr") == "banka.com.tr"
    assert mail.org_aligned("mail.banka.com.tr", "banka.com.tr", "r")
    assert not mail.org_aligned("mail.banka.com.tr", "banka.com.tr", "s")
    assert not mail.org_aligned("banka-evil.net", "banka.com.tr", "r")


def test_dmarc_passes_with_aligned_spf_and_reports_the_policy():
    dns = FakeDns({"_dmarc.banka.com.tr": ["v=DMARC1; p=reject; rua=mailto:r@banka.com.tr"]})
    assert mail.check_dmarc("banka.com.tr", "pass", "banka.com.tr", [], dns) == ("pass", "reject")
    assert mail.check_dmarc(
        "banka.com.tr", "fail", "banka.com.tr", [("evil.example", "pass")], dns
    ) == ("fail", "reject")
    assert mail.check_dmarc("kimse.example", "pass", "kimse.example", [], dns) == ("none", "")


def test_dkim_is_verified_on_the_original_bytes(signed):
    make, key_record = signed
    dns = FakeDns({"sel._domainkey.banka.com.tr": [key_record]})
    raw = make()
    assert mail.verify_signatures(raw, 1, dns) == ["pass"]
    assert mail.verify_signatures(raw.replace(b"Merhaba", b"Merhaba!"), 1, dns) == ["fail"]


def test_a_signed_mail_from_an_allowed_server_is_clean(signed, spf_dns):
    make, key_record = signed
    spf_dns["banka.com.tr"] = ["v=spf1 ip4:209.85.220.0/24 -all"]
    dns = FakeDns({
        "sel._domainkey.banka.com.tr": [key_record],
        "_dmarc.banka.com.tr": ["v=DMARC1; p=reject"],
    })
    raw = (
        b"Received: from mx.gmail.example (mx.gmail.example [209.85.220.41]) by mx.ours.example\r\n"
        b"Return-Path: <guvenlik@banka.com.tr>\r\n"
    ) + make()
    report = mail.analyze_mail(raw, use_dns=True, dns_client=dns)
    assert report.live == {"spf": "pass", "dkim": "pass", "dmarc": "pass"}
    assert report.dmarc_policy == "reject"
    assert report.verdict == "clean"


def test_display_name_showing_another_address_is_flagged():
    report = mail.analyze_mail(
        raw_mail(sender='"destek@banka.com.tr" <dolandirici@evil.example>'), use_dns=False
    )
    assert report.verdict == "suspicious"
    assert any(finding.title.startswith("Görünen ad") for finding in report.findings)


def test_without_authentication_data_the_verdict_is_insufficient():
    report = mail.analyze_mail(raw_mail(), use_dns=False)
    assert report.verdict == "insufficient"


def test_executable_attachment_is_suspicious():
    msg = EmailMessage()
    msg["From"] = "Muhasebe <muhasebe@example.org>"
    msg["Subject"] = "Fatura"
    msg.set_content("Ekteki faturayı açın")
    msg.add_attachment(b"MZ", maintype="application", subtype="octet-stream", filename="fatura.pdf.exe")
    report = mail.analyze_mail(msg.as_bytes(), use_dns=False)
    assert report.attachments[0].danger == ("bad", "Çalıştırılabilir ek")
    assert report.verdict == "suspicious"


def test_at_most_three_values_are_looked_up():
    body = "http://a.example.com/x http://b.example.net/y http://c.example.org/z http://d.example.io/w\n"
    report = mail.analyze_mail(raw_mail(*RECEIVED, body=body), use_dns=False)
    assert mail.lookup_targets(report) == [
        ("81.2.69.160", IOCType.IP),
        ("209.85.220.41", IOCType.IP),
        ("a.example.com", IOCType.DOMAIN),
    ]


def test_mail_page_opens(make_engine, monkeypatch):
    monkeypatch.setattr(api, "engine", make_engine())
    response = TestClient(api.app).get("/mail")
    assert response.status_code == 200
    assert "E-posta analizi" in response.text


def test_mail_page_analyzes_pasted_headers(make_engine, monkeypatch):
    monkeypatch.setattr(api, "engine", make_engine())
    response = TestClient(api.app).post(
        "/mail", data={"raw": "From: Banka <guvenlik@banka.com.tr>\nSubject: Test\n\nMerhaba"}
    )
    assert response.status_code == 200
    assert "Yetersiz veri" in response.text
    assert "guvenlik@banka.com.tr" in response.text


def test_mail_page_shows_links_attachments_and_lookups(make_engine, monkeypatch):
    monkeypatch.setattr(api, "engine", make_engine())
    msg = EmailMessage()
    msg["From"] = "Kargo <takip@kargo.example>"
    msg["Subject"] = "Paketiniz yolda"
    msg.set_content("Takip icin http://kargo-takip.example.net/abc adresine tiklayin")
    msg.add_attachment(b"MZ", maintype="application", subtype="octet-stream", filename="etiket.exe")
    response = TestClient(api.app).post(
        "/mail",
        files={"eml": ("mesaj.eml", msg.as_bytes(), "message/rfc822")},
        data={"enrich": "on"},
    )
    assert response.status_code == 200
    assert "kargo-takip.example.net" in response.text
    assert "etiket.exe" in response.text
    assert "Tehdit kaynaklarının sonucu" in response.text
    assert "Şüpheli" in response.text


def test_mail_page_rejects_empty_input(make_engine, monkeypatch):
    monkeypatch.setattr(api, "engine", make_engine())
    response = TestClient(api.app).post("/mail", data={"raw": "   "})
    assert response.status_code == 400
