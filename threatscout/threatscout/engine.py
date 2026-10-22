from __future__ import annotations

import asyncio
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from threatscout.config import Settings, get_settings
from threatscout.db import Store
from threatscout.models import (
    EnrichmentReport,
    IOCType,
    ProviderResult,
    RiskBreakdown,
    RiskLevel,
    cache_key,
    detect_ioc_type,
)
from threatscout.providers import BaseProvider, NVDClient, build_providers
from threatscout.webhooks import dispatch_webhook

CRITICAL_PORTS = {21, 22, 445, 3389, 23, 135, 139, 5900}


class SQLiteCache:
    def __init__(self, db_path: str) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS cache "
                "(key TEXT PRIMARY KEY, value TEXT NOT NULL, expires_at TEXT NOT NULL)"
            )

    async def get(self, key: str) -> dict[str, Any] | None:
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT value FROM cache WHERE key=? AND expires_at>?",
                (key, now),
            ).fetchone()
        return json.loads(row[0]) if row else None

    async def set(self, key: str, value: dict[str, Any], ttl_hours: int) -> None:
        expires = (datetime.now(timezone.utc) + timedelta(hours=ttl_hours)).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO cache (key, value, expires_at) VALUES (?,?,?)",
                (key, json.dumps(value), expires),
            )

    async def close(self) -> None:
        pass


class RiskScorer:
    IP_WEIGHTS = {
        "virustotal": 0.25,
        "abuseipdb": 0.25,
        "greynoise": 0.20,
        "shodan": 0.12,
        "otx": 0.10,
        "urlhaus": 0.04,
        "misp": 0.04,
    }
    HASH_WEIGHTS = {"virustotal": 0.50, "urlhaus": 0.25, "otx": 0.15, "misp": 0.10}
    DOMAIN_WEIGHTS = {"virustotal": 0.35, "urlhaus": 0.25, "otx": 0.20, "misp": 0.20}
    URL_WEIGHTS = {"virustotal": 0.35, "urlhaus": 0.35, "otx": 0.15, "misp": 0.15}
    EMAIL_WEIGHTS = {"otx": 0.60, "misp": 0.40}

    def enrich_report(self, report: EnrichmentReport) -> EnrichmentReport:
        scores: dict[str, float] = {}
        for r in report.providers:
            if not r.success or not r.normalized:
                continue
            n = r.normalized
            name = r.provider.lower()
            if name == "virustotal":
                total = n.get("total_engines", 0)
                scores["virustotal"] = (n.get("malicious", 0) / total * 100) if total else 0
            elif name == "abuseipdb":
                scores["abuseipdb"] = float(n.get("abuse_confidence", 0))
            elif name == "shodan":
                s = 0.0
                crit = set(n.get("open_ports", [])) & CRITICAL_PORTS
                if crit:
                    s += min(60, len(crit) * 20)
                cves = n.get("cves", [])
                if cves:
                    s += min(40, len(cves) * 10)
                if n.get("vulns"):
                    s += 20
                scores["shodan"] = min(100, s)
            elif name == "otx":
                pc = n.get("pulse_count", 0)
                scores["otx"] = min(100, pc * 15) if pc else 0
            elif name == "greynoise":
                cls = str(n.get("classification", "")).lower()
                if cls == "malicious":
                    scores["greynoise"] = 90.0
                elif n.get("riot") or cls == "benign":
                    scores["greynoise"] = 0.0
                elif n.get("noise") or cls == "unknown":
                    scores["greynoise"] = 35.0
                else:
                    scores["greynoise"] = 0.0
            elif name == "urlhaus":
                scores["urlhaus"] = 90.0 if n.get("listed") else 0.0
            elif name == "misp":
                count = n.get("event_count") or n.get("attribute_count") or 0
                scores["misp"] = min(100, int(count) * 20) if count else 0

        weights = {
            IOCType.IP: self.IP_WEIGHTS,
            IOCType.HASH: self.HASH_WEIGHTS,
            IOCType.DOMAIN: self.DOMAIN_WEIGHTS,
            IOCType.URL: self.URL_WEIGHTS,
            IOCType.EMAIL: self.EMAIL_WEIGHTS,
        }.get(report.ioc_type, self.IP_WEIGHTS)

        active = {k: v for k, v in weights.items() if k in scores}
        if not active:
            report.risk_breakdown = RiskBreakdown(weights_applied=weights)
            return report

        norm_w = {k: v / sum(active.values()) for k, v in active.items()}
        final = round(min(100, sum(scores[k] * norm_w[k] for k in active)), 1)

        report.threat_score = final
        report.risk_level = (
            RiskLevel.CRITICAL if final >= 80 else
            RiskLevel.HIGH if final >= 60 else
            RiskLevel.MEDIUM if final >= 40 else
            RiskLevel.LOW if final >= 1 else
            RiskLevel.CLEAN
        )
        report.risk_breakdown = RiskBreakdown(
            virustotal=scores.get("virustotal", 0),
            abuseipdb=scores.get("abuseipdb", 0),
            shodan=scores.get("shodan", 0),
            otx=scores.get("otx", 0),
            greynoise=scores.get("greynoise", 0),
            urlhaus=scores.get("urlhaus", 0),
            misp=scores.get("misp", 0),
            weights_applied=norm_w,
        )
        return report


class ThreatScoutEngine:
    def __init__(
        self,
        settings: Settings | None = None,
        providers: list[BaseProvider] | None = None,
        cache: SQLiteCache | None = None,
        store: Store | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.providers = providers or build_providers(self.settings)
        self.cache = cache or SQLiteCache(self.settings.sqlite_cache_path)
        self.store = store or Store(self.settings.sqlite_path)
        self.scorer = RiskScorer()
        self.nvd = NVDClient(self.settings.nvd_api_key, self.settings.request_timeout)

    async def close(self) -> None:
        await asyncio.gather(*[p.close() for p in self.providers], self.cache.close())

    async def enrich(
        self,
        ioc: str,
        ioc_type: IOCType | None = None,
        use_cache: bool = True,
        persist: bool = True,
        notify: bool = True,
    ) -> EnrichmentReport:
        ioc = ioc.strip()
        detected = ioc_type or detect_ioc_type(ioc)
        if detected == IOCType.UNKNOWN:
            return EnrichmentReport(ioc=ioc, ioc_type=IOCType.UNKNOWN)

        active = [p for p in self.providers if p.supports(detected)]
        results = await asyncio.gather(
            *[self._query(p, ioc, detected, use_cache) for p in active]
        )

        report = EnrichmentReport(
            ioc=ioc,
            ioc_type=detected,
            providers=list(results),
            cached=all(r.cached for r in results if r.success),
        )
        self._aggregate(report)
        self.scorer.enrich_report(report)
        await self._enrich_cves(report)
        if persist:
            self.store.save_scan(report)
        if persist and notify:
            await self._notify(report)
        return report

    async def _query(
        self, provider: BaseProvider, ioc: str, ioc_type: IOCType, use_cache: bool
    ) -> ProviderResult:
        key = cache_key(ioc, provider.name)
        if use_cache:
            cached = await self.cache.get(key)
            if cached:
                return ProviderResult(
                    provider=provider.name,
                    success=True,
                    cached=True,
                    raw=cached.get("raw", {}),
                    normalized=cached.get("normalized", {}),
                )
        result = await provider.analyze(ioc, ioc_type)
        if result.success and result.normalized and use_cache:
            await self.cache.set(
                key,
                {"raw": result.raw, "normalized": result.normalized},
                self.settings.cache_ttl_hours,
            )
        return result

    def _aggregate(self, report: EnrichmentReport) -> None:
        tags: set[str] = set()
        geo: dict[str, Any] = {}
        related: dict[str, list[str]] = {}
        whois: dict[str, Any] = {}
        for r in report.providers:
            if not r.success:
                continue
            for tag in r.normalized.get("tags", []):
                tags.add(str(tag))
            for cat in r.normalized.get("categories", []):
                if cat:
                    tags.add(str(cat))
            if not geo and r.normalized.get("country"):
                geo = {
                    "country": r.normalized.get("country", ""),
                    "city": r.normalized.get("city", ""),
                    "latitude": r.normalized.get("latitude"),
                    "longitude": r.normalized.get("longitude"),
                    "isp": r.normalized.get("isp", ""),
                }
            if r.provider == "whois":
                whois = r.normalized
                if r.normalized.get("nameservers"):
                    related["nameservers"] = list(r.normalized["nameservers"])
                if r.normalized.get("emails"):
                    related["emails"] = list(r.normalized["emails"])
        report.tags = sorted(tags)
        report.geo = geo
        report.related = related
        report.whois = whois

    async def _enrich_cves(self, report: EnrichmentReport) -> None:
        cves: list[str] = []
        for r in report.providers:
            if r.success:
                cves.extend(str(x) for x in (r.normalized.get("cves") or []))
        unique = list(dict.fromkeys(cves))
        if unique:
            report.cves = await self.nvd.lookup(unique)

    async def _notify(self, report: EnrichmentReport) -> None:
        hooks = self.store.enabled_webhooks()
        if not hooks:
            return
        payload = report.to_dict()
        for hook in hooks:
            try:
                detail = await dispatch_webhook(hook["kind"], hook["url"], hook["token"], payload)
                self.store.log_delivery(hook["id"], report.id, "ok", detail)
            except Exception as exc:
                self.store.log_delivery(hook["id"], report.id, "error", str(exc))
