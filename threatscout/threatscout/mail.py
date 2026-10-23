from __future__ import annotations

import email
import email.policy
import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from email.utils import parseaddr
from urllib.parse import urlparse

import dkim
import dns.exception
import dns.resolver
import dns.reversename
import spf

from threatscout.models import IOCType

MAX_MAIL_BYTES = 2 * 1024 * 1024
# VirusTotal'in ücretsiz sürümü dakikada sınırlı istek kabul eder, bu yüzden sorgu sayısı az tutulur
MAX_LOOKUPS = 3
DNS_LIFETIME = 5

EXECUTABLE_EXTENSIONS = {
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js",
    ".jse", ".wsf", ".hta", ".msi", ".lnk", ".jar", ".dll", ".iso", ".img",
}
MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xlam"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".gz", ".tar", ".tgz", ".cab"}
# İki parçalı uzantılar (ornek.com.tr gibi). Tam bir liste değil, yaygın olanlar.
MULTI_PART_SUFFIXES = {
    "com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr", "co.uk", "org.uk", "com.au", "co.jp", "com.br",
}

IP_IN_BRACKETS = re.compile(r"\[(?:IPv6:)?([0-9A-Fa-f:.]+)\]")
AUTH_RESULT = re.compile(r"\b(spf|dkim|dmarc)=(\w+)", re.IGNORECASE)
URL = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
DISPLAY_ADDRESS = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")

STATE_LABELS = {
    "pass": "Geçti",
    "fail": "Başarısız",
    "softfail": "Büyük ihtimalle yetkisiz",
    "neutral": "Karar vermedi",
    "none": "Kayıt yok",
    "temperror": "DNS geçici hata verdi",
    "permerror": "Kayıt hatalı",
    "unknown": "Belirsiz",
    "skipped": "Kontrol edilmedi",
}
# Sonuç: (başlık, renk sınıfı, açıklama)
VERDICTS = {
    "suspicious": (
        "Şüpheli",
        "bad",
        "Ciddi risk işaretleri var. Bağlantılara tıklamadan ve ekleri açmadan önce gönderenle başka bir yoldan konuşun.",
    ),
    "caution": (
        "Dikkat",
        "warn",
        "Bazı işaretler var. Mesajı gönderdiği söylenen kişiyle başka bir kanaldan doğrulayın.",
    ),
    "insufficient": (
        "Yetersiz veri",
        "unknown",
        "Kimlik doğrulama bilgisi bulunamadı. DNS kontrollerini açıp tekrar deneyin ya da ham .eml dosyasını yükleyin.",
    ),
    "clean": (
        "Sorun bulunmadı",
        "clean",
        "Kimlik doğrulama geçti ve belirgin bir risk işareti yok. Yine de beklenmedik isteklere karşı dikkatli olun.",
    ),
}
LEVEL_ORDER = {"bad": 0, "warn": 1, "info": 2, "ok": 3}


@dataclass
class Finding:
    level: str  # bad, warn, info ya da ok
    title: str
    detail: str = ""


@dataclass
class Attachment:
    name: str
    content_type: str
    size: int
    sha256: str

    @property
    def danger(self) -> tuple[str, str]:
        # "fatura.pdf.exe" gibi çift uzantıları da yakalamak için bütün parçalara bakılır
        suffixes = {"." + part for part in self.name.lower().split(".")[1:]}
        if suffixes & EXECUTABLE_EXTENSIONS:
            return "bad", "Çalıştırılabilir ek"
        if suffixes & MACRO_EXTENSIONS:
            return "bad", "Makro içerebilen belge"
        if suffixes & ARCHIVE_EXTENSIONS:
            return "warn", "Arşiv ek"
        return "ok", "Ek"


@dataclass
class Lookup:
    value: str
    kind: str
    risk: str
    score: float
    scan_id: int | None = None


@dataclass
class MailReport:
    source: str
    subject: str = ""
    from_name: str = ""
    sender: str = ""
    reply_to: str = ""
    return_path: str = ""
    to: str = ""
    date: str = ""
    message_id: str = ""
    hops: list[str] = field(default_factory=list)
    connecting_ip: str = ""
    connecting_ptr: str = ""
    origin_ip: str = ""
    origin_ptr: str = ""
    receiver_header: str = ""
    receiver: dict[str, str] = field(default_factory=dict)
    live: dict[str, str] = field(default_factory=dict)
    dmarc_policy: str = ""
    signatures: list[dict[str, str]] = field(default_factory=list)
    link_hosts: list[str] = field(default_factory=list)
    ip_links: list[str] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    lookups: list[Lookup] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    verdict: str = ""

    @property
    def verdict_label(self) -> str:
        return VERDICTS.get(self.verdict, ("", "", ""))[0]

    @property
    def verdict_css(self) -> str:
        return VERDICTS.get(self.verdict, ("", "", ""))[1]

    @property
    def verdict_text(self) -> str:
        return VERDICTS.get(self.verdict, ("", "", ""))[2]

    @property
    def auth(self) -> list[dict[str, str]]:
        return auth_rows(self)


class DnsClient:
    # Testlerde bu sınıfın yerine sabit kayıtlar veren bir nesne konur
    def __init__(self, lifetime: float = DNS_LIFETIME) -> None:
        self.lifetime = lifetime

    def txt(self, name: str) -> list[str]:
        try:
            answers = dns.resolver.resolve(name, "TXT", lifetime=self.lifetime)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        return [b"".join(item.strings).decode("utf-8", "replace") for item in answers]

    def ptr(self, ip: str) -> str:
        try:
            answers = dns.resolver.resolve(
                dns.reversename.from_address(ip), "PTR", lifetime=self.lifetime
            )
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return ""
        return answers[0].to_text().rstrip(".")


def _header(msg, name: str) -> str:
    return str(msg.get(name, "")).strip()


def _split_address(value: str) -> tuple[str, str]:
    name, address = parseaddr(value)
    return name.strip(), address.strip().lower()


def _domain(address: str) -> str:
    return address.rpartition("@")[2].lower()


def org_domain(domain: str) -> str:
    # Organizasyon alan adı: mail.banka.com.tr → banka.com.tr (basit kural)
    parts = domain.lower().strip(".").split(".")
    if len(parts) > 2 and ".".join(parts[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _is_public(value: str) -> bool:
    return _is_ip(value) and ipaddress.ip_address(value).is_global


def _hop_ip(hop: str) -> str:
    # Received satırında "from" ile "by" arasındaki ilk genel IP, o adımda bağlanan sunucudur
    match = re.search(r"\bfrom\b(.*?)(?:\bby\b|$)", hop, re.IGNORECASE | re.DOTALL)
    segment = match.group(1) if match else hop
    return next((ip for ip in IP_IN_BRACKETS.findall(segment) if _is_public(ip)), "")


def _connecting_ip(msg, hops: list[str]) -> str:
    # Alıcı sunucu "Received-SPF" başlığında bağlanan IP'yi yazar. Yoksa en üstteki Received'e bakılır.
    received_spf = msg.get_all("Received-SPF", [])
    match = re.search(r"client-ip=([0-9A-Fa-f:.]+)", str(received_spf[0])) if received_spf else None
    if match and _is_public(match.group(1)):
        return match.group(1)
    return next((ip for ip in map(_hop_ip, hops) if ip), "")


def _origin_ip(hops: list[str]) -> str:
    # En alttaki Received satırı mesajı ilk gönderen taraftır, ama bu satırı gönderen de yazabilir
    return next((ip for ip in map(_hop_ip, reversed(hops)) if ip), "")


def _receiver_results(msg) -> tuple[str, dict[str, str]]:
    # Yalnızca en üstteki Authentication-Results başlığına güvenilir; alttakileri gönderen ekleyebilir
    headers = msg.get_all("Authentication-Results", [])
    header = " ".join(str(headers[0]).split()) if headers else ""
    results: dict[str, str] = {}
    for name, value in AUTH_RESULT.findall(header):
        results.setdefault(name.lower(), value.lower())
    received_spf = msg.get_all("Received-SPF", [])
    if received_spf and "spf" not in results:
        results["spf"] = str(received_spf[0]).strip().split(" ", 1)[0].lower()
    return header, results


def _tags(text: str) -> dict[str, str]:
    # "d=ornek.com; s=sel" biçimindeki etiketleri sözlüğe çevirir
    tags = {}
    for part in text.split(";"):
        key, sep, value = part.partition("=")
        if sep:
            tags[key.strip().lower()] = "".join(value.split()).lower()
    return tags


def _dkim_signatures(msg) -> list[dict[str, str]]:
    return [
        {"domain": tags.get("d", ""), "selector": tags.get("s", "")}
        for tags in (_tags(str(value)) for value in msg.get_all("DKIM-Signature", []))
    ]


def check_spf(ip: str, sender: str) -> str:
    # pyspf RFC 7208 kurallarını uygular. Kesin karar verilemeyen durumlar "ambiguous" olur.
    if not ip or not sender:
        return "unknown"
    try:
        result, _explanation = spf.check2(i=ip, s=sender, h=_domain(sender))
    except dns.exception.DNSException:
        return "temperror"
    return "unknown" if result == "ambiguous" else result


def verify_signatures(raw: bytes, count: int, dns_client: DnsClient) -> list[str]:
    # Mesajın ham baytları kullanılır; başlıklar yeniden yazılırsa imza bozulur
    def lookup(name, timeout=DNS_LIFETIME):
        # dkimpy anahtarı bayt olarak ister ve isim sonunda nokta ile gelir
        records = dns_client.txt(name.decode().rstrip("."))
        return records[0].encode() if records else None

    results = []
    for index in range(count):
        try:
            valid = dkim.DKIM(raw, timeout=DNS_LIFETIME).verify(idx=index, dnsfunc=lookup)
            results.append("pass" if valid else "fail")
        except dkim.DnsTimeoutError:
            results.append("temperror")
        except dkim.DKIMException:
            results.append("fail")
        except dns.exception.DNSException:
            results.append("temperror")
    return results


def _overall_dkim(results: list[str]) -> str:
    if not results:
        return "none"
    if "pass" in results:
        return "pass"
    return "temperror" if "temperror" in results else "fail"


def org_aligned(domain: str, from_domain: str, mode: str) -> bool:
    if not domain or not from_domain:
        return False
    if mode == "s":
        return domain == from_domain
    return org_domain(domain) == org_domain(from_domain)


def find_dmarc(from_domain: str, dns_client: DnsClient) -> tuple[dict[str, str], bool]:
    # Önce gönderen alan adına, yoksa organizasyon alan adına bakılır
    names = [f"_dmarc.{from_domain}"]
    org = org_domain(from_domain)
    if org != from_domain:
        names.append(f"_dmarc.{org}")
    for index, name in enumerate(names):
        for record in dns_client.txt(name):
            if record.lower().startswith("v=dmarc1"):
                return _tags(record), index == 1
    return {}, False


def check_dmarc(
    from_domain: str,
    spf_result: str,
    spf_domain: str,
    pairs: list[tuple[str, str]],
    dns_client: DnsClient,
) -> tuple[str, str]:
    # Döner: (sonuç, politika). Sonuç pass, fail, none ya da temperror olabilir.
    if not from_domain:
        return "none", ""
    try:
        tags, at_org = find_dmarc(from_domain, dns_client)
    except dns.exception.DNSException:
        return "temperror", ""
    if not tags:
        return "none", ""
    policy = tags.get("sp", tags.get("p", "none")) if at_org else tags.get("p", "none")
    spf_ok = spf_result == "pass" and org_aligned(spf_domain, from_domain, tags.get("aspf", "r"))
    dkim_ok = any(
        result == "pass" and org_aligned(domain, from_domain, tags.get("adkim", "r"))
        for domain, result in pairs
    )
    return ("pass" if spf_ok or dkim_ok else "fail"), policy


def _collect_content(msg, report: MailReport) -> None:
    texts: list[str] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if filename:
            payload = part.get_payload(decode=True) or b""
            report.attachments.append(Attachment(
                name=filename,
                content_type=part.get_content_type(),
                size=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(),
            ))
        elif part.get_content_type() in ("text/plain", "text/html"):
            try:
                texts.append(str(part.get_content()))
            except (LookupError, ValueError):
                continue  # bozuk kodlamalı parçayı atla
    seen: set[str] = set()
    for url in URL.findall("\n".join(texts)):
        host = urlparse(url.rstrip(".,;:)]}")).hostname or ""
        if not host or host in seen:
            continue
        seen.add(host)
        if _is_ip(host):
            report.ip_links.append(host)
        else:
            report.link_hosts.append(host)


def _ptr(dns_client: DnsClient, ip: str) -> str:
    if not ip:
        return ""
    try:
        return dns_client.ptr(ip)
    except dns.exception.DNSException:
        return ""


def _live_checks(raw: bytes, report: MailReport, dns_client: DnsClient) -> None:
    # Bunlar mesajın bugün yeniden kontrolü. Alıcı sunucunun kararı daha önemlidir.
    envelope = report.return_path or report.sender
    report.live["spf"] = check_spf(report.connecting_ip, envelope)
    results = verify_signatures(raw, len(report.signatures), dns_client)
    report.live["dkim"] = _overall_dkim(results)
    pairs = [(sig["domain"], result) for sig, result in zip(report.signatures, results)]
    report.live["dmarc"], report.dmarc_policy = check_dmarc(
        _domain(report.sender), report.live["spf"], _domain(envelope), pairs, dns_client
    )
    report.connecting_ptr = _ptr(dns_client, report.connecting_ip)
    report.origin_ptr = _ptr(dns_client, report.origin_ip)


def analyze_mail(
    raw: bytes,
    source: str = "file",
    use_dns: bool = True,
    dns_client: DnsClient | None = None,
) -> MailReport:
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    report = MailReport(source=source)
    report.subject = _header(msg, "Subject")
    report.from_name, report.sender = _split_address(_header(msg, "From"))
    _, report.return_path = _split_address(_header(msg, "Return-Path"))
    _, report.reply_to = _split_address(_header(msg, "Reply-To"))
    report.to = _header(msg, "To")
    report.date = _header(msg, "Date")
    report.message_id = _header(msg, "Message-ID")
    report.hops = [" ".join(str(value).split()) for value in msg.get_all("Received", [])]
    report.connecting_ip = _connecting_ip(msg, report.hops)
    report.origin_ip = _origin_ip(report.hops)
    report.receiver_header, report.receiver = _receiver_results(msg)
    report.signatures = _dkim_signatures(msg)
    _collect_content(msg, report)
    if use_dns:
        _live_checks(raw, report, dns_client or DnsClient())
    return finalize(report)


def lookup_targets(report: MailReport) -> list[tuple[str, IOCType]]:
    # Önce IP'ler (gönderen ve bağlanan sunucu), sonra bağlantılar ve ekler. En fazla MAX_LOOKUPS değer.
    targets: list[tuple[str, IOCType]] = []
    for ip in dict.fromkeys(ip for ip in (report.origin_ip, report.connecting_ip) if ip):
        targets.append((ip, IOCType.IP))
    targets += [(host, IOCType.DOMAIN) for host in report.link_hosts]
    targets += [(item.sha256, IOCType.HASH) for item in report.attachments]
    return targets[:MAX_LOOKUPS]


def _primary(report: MailReport, name: str) -> str:
    # Alıcı sunucunun kararı varsa o öncelikli. Yoksa bizim şimdiki kontrolümüz kullanılır.
    return report.receiver.get(name) or report.live.get(name, "skipped")


def _label(key: str, state: str) -> str:
    if key == "dkim" and state == "none":
        return "İmza yok"
    return STATE_LABELS.get(state, state)


def auth_rows(report: MailReport) -> list[dict[str, str]]:
    rows = []
    for key, title in (("spf", "SPF"), ("dkim", "DKIM"), ("dmarc", "DMARC")):
        primary = _primary(report, key)
        rows.append({
            "title": title,
            "state": _label(key, primary),
            "css": "is-ok" if primary == "pass" else "is-fail" if primary in ("fail", "softfail") else "is-off",
            "receiver": _label(key, report.receiver[key]) if key in report.receiver else "Başlık yok",
            "live": _label(key, report.live[key]) if key in report.live else "Kontrol edilmedi",
        })
    return rows


def _lookup_finding(item: Lookup) -> Finding:
    if item.risk in ("CRITICAL", "HIGH"):
        return Finding("bad", f"{item.value} yüksek riskli görünüyor", f"Risk {item.risk}, puan {item.score:.0f}/100.")
    if item.risk == "MEDIUM":
        return Finding("warn", f"{item.value} orta riskli", f"Puan {item.score:.0f}/100.")
    if item.risk == "CLEAN":
        return Finding("ok", f"{item.value} temiz görünüyor", "Kaynaklar bu değerle ilgili kötü bir kayıt bulmadı.")
    if item.risk == "LOW":
        return Finding("info", f"{item.value} düşük riskli", f"Puan {item.score:.0f}/100.")
    return Finding("info", f"{item.value} hakkında yeterli veri yok", "Kaynaklar bu değeri bilmiyor ya da yanıt vermedi.")


def build_findings(report: MailReport) -> list[Finding]:
    findings: list[Finding] = []

    spf_state = _primary(report, "spf")
    if spf_state == "pass":
        findings.append(Finding("ok", "SPF geçti", "Gönderen sunucu, alan adının yetkili sunucularından biri."))
    elif spf_state in ("fail", "softfail"):
        findings.append(Finding("warn", "SPF geçmedi", "Bu sunucu, gönderen alan adı adına mail gönderme yetkisine sahip olmayabilir."))
    elif spf_state == "none":
        findings.append(Finding("info", "SPF kaydı yok", "Gönderen alan adı SPF kaydı yayımlamamış."))
    elif spf_state == "temperror":
        findings.append(Finding("info", "SPF kontrol edilemedi", "DNS sorgusu zaman aşımına uğradı."))

    dkim_state = _primary(report, "dkim")
    if dkim_state == "pass":
        findings.append(Finding("ok", "DKIM imzası geçerli", "Mesaj imzalandığı haliyle değişmemiş."))
    elif dkim_state == "fail" and report.source == "text" and not report.receiver.get("dkim"):
        findings.append(Finding("info", "DKIM doğrulanamadı", "Metin yapıştırıldığında imza bozulabilir. Ham .eml dosyasını yüklerseniz kesin sonuç alırsınız."))
    elif dkim_state == "fail":
        findings.append(Finding("warn", "DKIM imzası geçersiz", "İmza bozulmuş ya da anahtarı bulunamamış. Mesaj yolda değişmiş olabilir."))
    elif dkim_state == "none":
        findings.append(Finding("info", "DKIM imzası yok", "Mesaj dijital olarak imzalanmamış."))

    dmarc_state = _primary(report, "dmarc")
    if dmarc_state == "pass":
        findings.append(Finding("ok", "DMARC geçti", "SPF ya da DKIM, gönderen adresiyle uyumlu."))
    elif dmarc_state == "fail":
        level = "bad" if report.dmarc_policy in ("reject", "quarantine") else "warn"
        policy = report.dmarc_policy or "bilinmiyor"
        findings.append(Finding(level, "DMARC geçmedi", f"Gönderen alan adının DMARC kuralı karşılanmadı. Politika: {policy}."))
    elif dmarc_state == "none":
        findings.append(Finding("info", "DMARC kaydı yok", "Gönderen alan adı DMARC kaydı yayımlamamış."))

    shown = DISPLAY_ADDRESS.search(report.from_name)
    if shown and shown.group(0).lower() != report.sender:
        findings.append(Finding(
            "bad",
            "Görünen ad başka bir adresi taklit ediyor",
            f"Görünen adda {shown.group(0)} yazıyor, ama mesaj {report.sender} adresinden geliyor.",
        ))
    if report.reply_to and org_domain(_domain(report.reply_to)) != org_domain(_domain(report.sender)):
        findings.append(Finding("warn", "Yanıt adresi farklı bir alan adında", f"Yanıtlar {report.reply_to} adresine gidecek."))
    if report.return_path and org_domain(_domain(report.return_path)) != org_domain(_domain(report.sender)):
        findings.append(Finding("info", "Dönüş adresi farklı", "Toplu gönderim servisleri için normal olabilir. DMARC sonucuna bakın."))
    for host in [_domain(report.sender), *report.link_hosts]:
        if "xn--" in host:
            findings.append(Finding("warn", "Alan adı benzer harflerle yazılmış olabilir", f"{host} özel karakterli bir alan adı (xn-- ile başlıyor)."))
    if report.ip_links:
        findings.append(Finding("warn", "Bağlantılar doğrudan IP adresine gidiyor", ", ".join(report.ip_links[:3])))

    for item in report.attachments:
        level, label = item.danger
        if level != "ok":
            detail = (
                "Bu tür dosyalar genellikle zararlı yazılım taşır."
                if level == "bad"
                else "Arşivin içinde çalıştırılabilir dosya saklanmış olabilir."
            )
            findings.append(Finding(level, f"{label}: {item.name}", detail))

    findings += [_lookup_finding(item) for item in report.lookups]
    return sorted(findings, key=lambda finding: LEVEL_ORDER[finding.level])


def verdict_for(report: MailReport) -> str:
    levels = {finding.level for finding in report.findings}
    if "bad" in levels:
        return "suspicious"
    if "warn" in levels:
        return "caution"
    # Hiçbir kimlik doğrulama sonucu yoksa "temiz" demek yanıltıcı olur
    if not any(_primary(report, key) in ("pass", "fail", "softfail") for key in ("spf", "dkim", "dmarc")):
        return "insufficient"
    return "clean"


def finalize(report: MailReport) -> MailReport:
    report.findings = build_findings(report)
    report.verdict = verdict_for(report)
    return report


def add_lookups(report: MailReport, lookups: list[Lookup]) -> MailReport:
    report.lookups = lookups
    return finalize(report)
