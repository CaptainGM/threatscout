from threatscout.engine import RiskScorer
from threatscout.models import EnrichmentReport, IOCType, ProviderResult, RiskLevel
from threatscout.providers import OTXProvider, ShodanProvider
from threatscout.report import provider_detail, result_context


def _report(ioc_type, *providers):
    return EnrichmentReport(ioc="ornek", ioc_type=ioc_type, providers=list(providers))


def _ok(provider, normalized):
    return ProviderResult(provider=provider, success=True, normalized=normalized)


def test_otx_without_pulses_is_not_counted_as_clean():
    # OTX "rapor yok" diyorsa bu temiz demek değildir, sonuç bilinmiyor kalmalı
    report = _report(IOCType.IP, _ok("otx", {"pulse_count": 0}))
    assert RiskScorer().enrich_report(report).risk_level == RiskLevel.UNKNOWN


def test_urlhaus_not_listed_is_not_counted_as_clean():
    report = _report(IOCType.DOMAIN, _ok("urlhaus", {"listed": False, "query_status": "no_results"}))
    assert RiskScorer().enrich_report(report).risk_level == RiskLevel.UNKNOWN


def test_otx_pulses_do_not_raise_a_domain_score():
    # wikipedia.org gibi çok bilinen sitelerde rapor sayısı yüksek çıkar, puana girmemeli
    report = _report(
        IOCType.DOMAIN,
        _ok("virustotal", {"malicious": 0, "total_engines": 90}),
        _ok("otx", {"pulse_count": 50}),
    )
    result = RiskScorer().enrich_report(report)
    assert result.risk_level == RiskLevel.CLEAN
    assert result.threat_score == 0


def test_urlhaus_domain_listing_is_ignored_when_virustotal_is_clean():
    report = _report(
        IOCType.DOMAIN,
        _ok("virustotal", {"malicious": 0, "total_engines": 90}),
        _ok("urlhaus", {"listed": True, "query_status": "ok"}),
    )
    assert RiskScorer().enrich_report(report).risk_level == RiskLevel.CLEAN


def test_urlhaus_domain_listing_counts_when_virustotal_flags_it():
    report = _report(
        IOCType.DOMAIN,
        _ok("virustotal", {"malicious": 19, "total_engines": 90}),
        _ok("urlhaus", {"listed": True, "query_status": "ok"}),
    )
    result = RiskScorer().enrich_report(report)
    assert result.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)


def test_known_bad_hash_is_not_diluted_by_empty_sources():
    # EICAR gibi bilinen bir dosyada VirusTotal ve OTX zararlı diyor, URLhaus ise listede yok diyor
    report = _report(
        IOCType.HASH,
        _ok("virustotal", {"malicious": 40, "total_engines": 70}),
        _ok("otx", {"pulse_count": 50}),
        _ok("urlhaus", {"listed": False, "query_status": "no_results"}),
    )
    result = RiskScorer().enrich_report(report)
    assert result.risk_level == RiskLevel.CRITICAL
    assert result.threat_score == 100


def test_otx_result_for_a_domain_is_marked_as_context():
    provider = OTXProvider("anahtar")
    normalized = provider.normalize({"pulse_info": {"count": 50, "pulses": []}}, IOCType.DOMAIN)
    assert normalized["context_only"] is True
    assert provider_detail(_ok("otx", normalized)) == "50 tehdit raporunda geçiyor, puana katılmaz"


def test_shodan_ports_of_a_shared_server_do_not_raise_a_clean_domain():
    # github.com'un IP'sinde SSH (22) açık: bu sitenin kendi değil, sunucunun özelliği
    report = _report(
        IOCType.DOMAIN,
        _ok("virustotal", {"malicious": 0, "total_engines": 90}),
        _ok("shodan", {"open_ports": [22, 443], "cves": [], "vulns": False, "context_only": True}),
    )
    result = RiskScorer().enrich_report(report)
    assert result.risk_level == RiskLevel.CLEAN
    assert result.threat_score == 0


def test_clean_result_reports_how_many_sources_scored_it():
    # Yalnızca VirusTotal puan verdiyse temiz sonucun uyarısı bunu söylemeli (OTX puan vermez)
    report = _report(
        IOCType.DOMAIN,
        _ok("virustotal", {"malicious": 0, "total_engines": 90}),
        _ok("otx", {"pulse_count": 50}),
    )
    RiskScorer().enrich_report(report)
    assert result_context(report)["coverage"]["scoring"] == 1


def test_shodan_403_message_says_the_free_plan_may_block_it():
    message = ShodanProvider("anahtar")._http_error(403)
    assert "izin vermedi" in message
    assert "Ücretsiz planda" in message
