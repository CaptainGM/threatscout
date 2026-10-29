from __future__ import annotations

import base64
from abc import ABC, abstractmethod
from typing import Any
from urllib.parse import quote, urlparse

import httpx

from threatscout.models import DISABLED_ERROR, IOCType, ProviderResult


def _skipped() -> dict[str, Any]:
    return {"skipped": True}


def _http_message(code: int) -> str:
    if code in (401, 403):
        return f"Anahtar geçersiz ya da bu sorgu için yetki yok ({code})"
    if code == 429:
        return "Istek limiti doldu (429)"
    return f"HTTP {code}"


class BaseProvider(ABC):
    name: str = "base"
    requires_key: bool = True

    def __init__(self, api_key: str | None = None, timeout: float = 15.0) -> None:
        self.api_key = (api_key or "").strip()
        self.enabled = bool(self.api_key) if self.requires_key else True
        self.timeout = timeout
        self._client: httpx.AsyncClient | None = None

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=self.timeout, follow_redirects=True)
        return self._client

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    def supports(self, ioc_type: IOCType) -> bool:
        return True

    def _http_error(self, code: int) -> str:
        return _http_message(code)

    async def analyze(self, ioc: str, ioc_type: IOCType) -> ProviderResult:
        if not self.enabled:
            return ProviderResult(provider=self.name, success=False, error=DISABLED_ERROR)
        try:
            handlers = {
                IOCType.IP: self.analyze_ip,
                IOCType.DOMAIN: self.analyze_domain,
                IOCType.URL: self.analyze_url,
                IOCType.HASH: self.analyze_hash,
                IOCType.EMAIL: self.analyze_email,
            }
            handler = handlers.get(ioc_type)
            if not handler:
                return ProviderResult(provider=self.name, success=False, error="Desteklenmeyen tip")
            raw = await handler(ioc)
            if raw.get("skipped"):
                return ProviderResult(provider=self.name, success=True, raw=raw, normalized={})
            return ProviderResult(
                provider=self.name,
                success=True,
                raw=raw,
                normalized=self.normalize(raw, ioc_type),
            )
        except httpx.HTTPStatusError as exc:
            return ProviderResult(
                provider=self.name,
                success=False,
                error=self._http_error(exc.response.status_code),
            )
        except httpx.TimeoutException:
            return ProviderResult(provider=self.name, success=False, error="Zaman asimi, cevap gelmedi")
        except Exception as exc:
            return ProviderResult(provider=self.name, success=False, error=str(exc))

    @abstractmethod
    async def analyze_ip(self, ip: str) -> dict[str, Any]: ...

    @abstractmethod
    async def analyze_domain(self, domain: str) -> dict[str, Any]: ...

    @abstractmethod
    async def analyze_url(self, url: str) -> dict[str, Any]: ...

    @abstractmethod
    async def analyze_hash(self, file_hash: str) -> dict[str, Any]: ...

    async def analyze_email(self, email: str) -> dict[str, Any]:
        return _skipped()

    @abstractmethod
    def normalize(self, raw: dict[str, Any], ioc_type: IOCType) -> dict[str, Any]: ...


class VirusTotalProvider(BaseProvider):
    name = "virustotal"

    async def _get(self, path: str) -> dict[str, Any]:
        r = await self.client.get(
            f"https://www.virustotal.com/api/v3{path}",
            headers={"x-apikey": self.api_key},
        )
        r.raise_for_status()
        return r.json()

    async def analyze_ip(self, ip: str) -> dict[str, Any]:
        return await self._get(f"/ip_addresses/{ip}")

    async def analyze_domain(self, domain: str) -> dict[str, Any]:
        return await self._get(f"/domains/{domain}")

    async def analyze_url(self, url: str) -> dict[str, Any]:
        uid = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        return await self._get(f"/urls/{uid}")

    async def analyze_hash(self, file_hash: str) -> dict[str, Any]:
        return await self._get(f"/files/{file_hash}")

    def normalize(self, raw: dict[str, Any], ioc_type: IOCType) -> dict[str, Any]:
        attrs = raw.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "malicious": stats.get("malicious", 0),
            "total_engines": sum(stats.values()) if stats else 0,
            "country": attrs.get("country", ""),
            "tags": attrs.get("tags", []),
            "categories": list(attrs.get("categories", {}).values()),
        }

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type in {IOCType.IP, IOCType.DOMAIN, IOCType.URL, IOCType.HASH}


class AbuseIPDBProvider(BaseProvider):
    name = "abuseipdb"

    async def analyze_ip(self, ip: str) -> dict[str, Any]:
        r = await self.client.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": self.api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
        )
        r.raise_for_status()
        return r.json()

    async def analyze_domain(self, domain: str) -> dict[str, Any]:
        return _skipped()

    async def analyze_url(self, url: str) -> dict[str, Any]:
        return _skipped()

    async def analyze_hash(self, file_hash: str) -> dict[str, Any]:
        return _skipped()

    def normalize(self, raw: dict[str, Any], ioc_type: IOCType) -> dict[str, Any]:
        data = raw.get("data", {})
        return {
            "abuse_confidence": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country": data.get("countryCode", ""),
            "isp": data.get("isp", ""),
            "categories": [r.get("category", "") for r in data.get("reports", [])[:10]],
        }

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type == IOCType.IP


class ShodanProvider(BaseProvider):
    name = "shodan"

    def _http_error(self, code: int) -> str:
        if code == 403:
            return "Shodan bu sorguya izin vermedi (403). Ücretsiz planda bazı sorgular kapalı olabilir."
        return super()._http_error(code)

    async def analyze_ip(self, ip: str) -> dict[str, Any]:
        r = await self.client.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": self.api_key},
        )
        r.raise_for_status()
        return r.json()

    async def analyze_domain(self, domain: str) -> dict[str, Any]:
        r = await self.client.get(
            "https://api.shodan.io/dns/resolve",
            params={"hostnames": domain, "key": self.api_key},
        )
        r.raise_for_status()
        ip = r.json().get(domain)
        return await self.analyze_ip(ip) if ip else {"error": "resolve failed"}

    async def analyze_url(self, url: str) -> dict[str, Any]:
        host = urlparse(url).hostname
        return await self.analyze_domain(host) if host else {"error": "bad url"}

    async def analyze_hash(self, file_hash: str) -> dict[str, Any]:
        return _skipped()

    def normalize(self, raw: dict[str, Any], ioc_type: IOCType) -> dict[str, Any]:
        if raw.get("error"):
            return {}
        vulns = raw.get("vulns", []) or []
        if isinstance(vulns, dict):
            vulns = list(vulns.keys())
        return {
            "open_ports": raw.get("ports", []),
            "cves": [v for v in vulns if str(v).upper().startswith("CVE-")],
            "vulns": bool(vulns),
            "context_only": ioc_type in (IOCType.DOMAIN, IOCType.URL),
            "country": raw.get("country_name", ""),
            "city": raw.get("city", ""),
            "latitude": raw.get("latitude"),
            "longitude": raw.get("longitude"),
            "isp": raw.get("isp", raw.get("org", "")),
            "tags": raw.get("tags", []),
        }

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type in {IOCType.IP, IOCType.DOMAIN, IOCType.URL}


class OTXProvider(BaseProvider):
    name = "otx"

    async def _get(self, kind: str, value: str) -> dict[str, Any]:
        r = await self.client.get(
            f"https://otx.alienvault.com/api/v1/indicators/{kind}/{value}/general",
            headers={"X-OTX-API-KEY": self.api_key},
        )
        r.raise_for_status()
        return r.json()

    async def analyze_ip(self, ip: str) -> dict[str, Any]:
        return await self._get("IPv4", ip)

    async def analyze_domain(self, domain: str) -> dict[str, Any]:
        return await self._get("domain", domain)

    async def analyze_url(self, url: str) -> dict[str, Any]:
        return await self._get("url", quote(url, safe=""))

    async def analyze_hash(self, file_hash: str) -> dict[str, Any]:
        return await self._get("file", file_hash)

    async def analyze_email(self, email: str) -> dict[str, Any]:
        return await self._get("email", email)

    def normalize(self, raw: dict[str, Any], ioc_type: IOCType) -> dict[str, Any]:
        tags: set[str] = set()
        for pulse in raw.get("pulse_info", {}).get("pulses", [])[:20]:
            tags.update(pulse.get("tags", []))
        return {
            "pulse_count": raw.get("pulse_info", {}).get("count", 0),
            "context_only": ioc_type in (IOCType.DOMAIN, IOCType.URL),
            "tags": sorted(tags),
            "country": raw.get("country_name", ""),
            "city": raw.get("city", ""),
            "latitude": raw.get("latitude"),
            "longitude": raw.get("longitude"),
        }

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type in {
            IOCType.IP, IOCType.DOMAIN, IOCType.URL, IOCType.HASH, IOCType.EMAIL
        }


class GreyNoiseProvider(BaseProvider):
    name = "greynoise"

    async def analyze_ip(self, ip: str) -> dict[str, Any]:
        r = await self.client.get(
            f"https://api.greynoise.io/v3/community/{ip}",
            headers={"key": self.api_key, "Accept": "application/json"},
        )
        r.raise_for_status()
        return r.json()

    async def analyze_domain(self, domain: str) -> dict[str, Any]:
        return _skipped()

    async def analyze_url(self, url: str) -> dict[str, Any]:
        return _skipped()

    async def analyze_hash(self, file_hash: str) -> dict[str, Any]:
        return _skipped()

    def normalize(self, raw: dict[str, Any], ioc_type: IOCType) -> dict[str, Any]:
        classification = str(raw.get("classification", "unknown")).lower()
        tags = [classification]
        if raw.get("noise"):
            tags.append("noise")
        if raw.get("riot"):
            tags.append("riot")
        return {
            "classification": classification,
            "noise": bool(raw.get("noise")),
            "riot": bool(raw.get("riot")),
            "name": raw.get("name", ""),
            "tags": tags,
        }

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type == IOCType.IP


class URLhausProvider(BaseProvider):
    name = "urlhaus"

    def _headers(self) -> dict[str, str]:
        if self.api_key:
            return {"Auth-Key": self.api_key}
        return {}

    async def _post(self, path: str, data: dict[str, str]) -> dict[str, Any]:
        r = await self.client.post(
            f"https://urlhaus-api.abuse.ch/v1/{path}",
            data=data,
            headers=self._headers(),
        )
        r.raise_for_status()
        return r.json()

    async def analyze_ip(self, ip: str) -> dict[str, Any]:
        return await self._post("host/", {"host": ip})

    async def analyze_domain(self, domain: str) -> dict[str, Any]:
        return await self._post("host/", {"host": domain})

    async def analyze_url(self, url: str) -> dict[str, Any]:
        return await self._post("url/", {"url": url})

    async def analyze_hash(self, file_hash: str) -> dict[str, Any]:
        key = "md5_hash" if len(file_hash) == 32 else "sha256_hash"
        return await self._post("payload/", {key: file_hash})

    def normalize(self, raw: dict[str, Any], ioc_type: IOCType) -> dict[str, Any]:
        status = raw.get("query_status", "")
        listed = status in {"ok", "listed"}
        tags = list(raw.get("tags") or [])
        urls = raw.get("urls") or []
        return {
            "listed": listed,
            "query_status": status,
            "threat": raw.get("threat", ""),
            "url_count": len(urls) if isinstance(urls, list) else 0,
            "tags": tags,
        }

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type in {IOCType.IP, IOCType.DOMAIN, IOCType.URL, IOCType.HASH}


class MISPProvider(BaseProvider):
    name = "misp"

    def __init__(self, api_key: str | None = None, timeout: float = 15.0, base_url: str = "") -> None:
        super().__init__(api_key, timeout)
        self.base_url = (base_url or "").rstrip("/")
        self.enabled = bool(self.api_key and self.base_url)

    async def _search(self, value: str) -> dict[str, Any]:
        r = await self.client.post(
            f"{self.base_url}/attributes/restSearch",
            headers={
                "Authorization": self.api_key,
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            json={"value": value, "limit": 25, "returnFormat": "json"},
        )
        r.raise_for_status()
        return r.json()

    async def analyze_ip(self, ip: str) -> dict[str, Any]:
        return await self._search(ip)

    async def analyze_domain(self, domain: str) -> dict[str, Any]:
        return await self._search(domain)

    async def analyze_url(self, url: str) -> dict[str, Any]:
        return await self._search(url)

    async def analyze_hash(self, file_hash: str) -> dict[str, Any]:
        return await self._search(file_hash)

    async def analyze_email(self, email: str) -> dict[str, Any]:
        return await self._search(email)

    def normalize(self, raw: dict[str, Any], ioc_type: IOCType) -> dict[str, Any]:
        attrs = raw.get("response", {}).get("Attribute", [])
        if isinstance(raw.get("Attribute"), list):
            attrs = raw["Attribute"]
        event_ids = {str(a.get("event_id")) for a in attrs if a.get("event_id")}
        tags = []
        for a in attrs[:20]:
            for t in a.get("Tag", []) or []:
                name = t.get("name") if isinstance(t, dict) else str(t)
                if name:
                    tags.append(name)
        return {
            "attribute_count": len(attrs),
            "event_count": len(event_ids),
            "tags": sorted(set(tags)),
        }

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type != IOCType.UNKNOWN


class WhoisProvider(BaseProvider):
    name = "whois"
    requires_key = False

    def __init__(self, api_key: str | None = None, timeout: float = 15.0) -> None:
        super().__init__(api_key, timeout)
        self.enabled = True

    async def _rdap(self, path: str) -> dict[str, Any]:
        r = await self.client.get(f"https://rdap.org/{path}")
        r.raise_for_status()
        return r.json()

    async def analyze_ip(self, ip: str) -> dict[str, Any]:
        return await self._rdap(f"ip/{ip}")

    async def analyze_domain(self, domain: str) -> dict[str, Any]:
        return await self._rdap(f"domain/{domain}")

    async def analyze_url(self, url: str) -> dict[str, Any]:
        host = urlparse(url).hostname
        return await self.analyze_domain(host) if host else {"error": "bad url"}

    async def analyze_hash(self, file_hash: str) -> dict[str, Any]:
        return _skipped()

    async def analyze_email(self, email: str) -> dict[str, Any]:
        domain = email.split("@", 1)[-1]
        data = await self.analyze_domain(domain)
        data["email"] = email
        data["mailbox_domain"] = domain
        return data

    def normalize(self, raw: dict[str, Any], ioc_type: IOCType) -> dict[str, Any]:
        if raw.get("error"):
            return {}
        vcard_names = []
        emails = []
        for ent in raw.get("entities") or []:
            vcard = (ent.get("vcardArray") or [None, []])[1]
            for item in vcard:
                if not isinstance(item, list) or len(item) < 4:
                    continue
                if item[0] == "fn":
                    vcard_names.append(str(item[3]))
                if item[0] == "email":
                    emails.append(str(item[3]))
        nameservers = [
            ns.get("ldhName", "") for ns in (raw.get("nameservers") or []) if ns.get("ldhName")
        ]
        created = next(
            (
                e.get("eventDate", "")[:10]
                for e in raw.get("events") or []
                if e.get("eventAction") == "registration"
            ),
            "",
        )
        return {
            "handle": raw.get("handle", ""),
            "name": raw.get("name", "") or (vcard_names[0] if vcard_names else ""),
            "registrar": next((n for n in vcard_names if n), ""),
            "status": raw.get("status") or [],
            "nameservers": nameservers,
            "emails": emails,
            "country": str(raw.get("country") or ""),
            "created": created,
            "mailbox_domain": raw.get("mailbox_domain", ""),
        }

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type in {IOCType.IP, IOCType.DOMAIN, IOCType.URL, IOCType.EMAIL}


def _cert_summary(domain: str, certs: list[dict[str, Any]]) -> dict[str, Any]:
    # crt.sh yüzlerce satır dönebilir; kaydetmek için yalnızca özet tutuyoruz
    names: set[str] = set()
    for cert in certs:
        for name in str(cert.get("name_value", "")).splitlines():
            name = name.strip().lower().lstrip("*.")
            if name and (name == domain or name.endswith("." + domain)):
                names.add(name)
    dated = [cert for cert in certs if cert.get("not_before")]
    latest = max(dated, key=lambda cert: cert["not_before"], default=None)
    return {
        "cert_count": len(certs),
        "subdomain_count": len(names),
        "first_seen": min((cert["not_before"][:10] for cert in dated), default=""),
        "issuer": str(latest.get("issuer_name", "")) if latest else "",
        "tags": [],
    }


class CrtShProvider(BaseProvider):
    # Sertifika şeffaflığı kayıtları (crt.sh). Anahtar gerektirmez ve puanlamaya girmez,
    # alan adının sertifika geçmişi ve alt alan adları hakkında bağlam verir.
    name = "crtsh"
    requires_key = False

    async def analyze_domain(self, domain: str) -> dict[str, Any]:
        r = await self.client.get(
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
        )
        r.raise_for_status()
        return _cert_summary(domain.lower(), r.json())

    async def analyze_ip(self, ip: str) -> dict[str, Any]:
        return _skipped()

    async def analyze_url(self, url: str) -> dict[str, Any]:
        host = urlparse(url).hostname
        return await self.analyze_domain(host) if host else {"error": "bad url"}

    async def analyze_hash(self, file_hash: str) -> dict[str, Any]:
        return _skipped()

    def normalize(self, raw: dict[str, Any], ioc_type: IOCType) -> dict[str, Any]:
        if raw.get("error"):
            return {}
        return dict(raw)

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type in {IOCType.DOMAIN, IOCType.URL}


class NVDClient:
    def __init__(self, api_key: str = "", timeout: float = 15.0) -> None:
        self.api_key = api_key.strip()
        self.timeout = timeout

    async def lookup(self, cve_ids: list[str], limit: int = 5) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        headers = {"apiKey": self.api_key} if self.api_key else {}
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            for cve_id in cve_ids[:limit]:
                try:
                    r = await client.get(
                        "https://services.nvd.nist.gov/rest/json/cves/2.0",
                        params={"cveId": cve_id},
                        headers=headers,
                    )
                    r.raise_for_status()
                    vulns = r.json().get("vulnerabilities") or []
                    if not vulns:
                        out.append({"id": cve_id, "summary": "NVD kaydi yok"})
                        continue
                    cve = vulns[0].get("cve", {})
                    descs = cve.get("descriptions") or []
                    summary = next((d["value"] for d in descs if d.get("lang") == "en"), "")
                    metrics = cve.get("metrics") or {}
                    score = None
                    severity = ""
                    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                        items = metrics.get(key) or []
                        if items:
                            data = items[0].get("cvssData") or {}
                            score = data.get("baseScore")
                            severity = data.get("baseSeverity") or items[0].get("baseSeverity") or ""
                            break
                    out.append({
                        "id": cve_id,
                        "summary": summary[:400],
                        "score": score,
                        "severity": severity,
                        "published": cve.get("published", ""),
                    })
                except Exception as exc:
                    out.append({"id": cve_id, "summary": str(exc), "error": True})
        return out


def build_providers(settings) -> list[BaseProvider]:
    t = settings.request_timeout
    return [
        VirusTotalProvider(settings.virustotal_api_key, t),
        AbuseIPDBProvider(settings.abuseipdb_api_key, t),
        ShodanProvider(settings.shodan_api_key, t),
        OTXProvider(settings.otx_api_key, t),
        GreyNoiseProvider(settings.greynoise_api_key, t),
        URLhausProvider(settings.urlhaus_api_key, t),
        MISPProvider(settings.misp_api_key, t, settings.misp_url),
        WhoisProvider("", t),
        CrtShProvider("", t),
    ]
