import pytest

from threatscout.models import DISABLED_ERROR, EnrichmentReport, IOCType, ProviderResult, RiskLevel
from threatscout.report import coverage, gauge, graph, provider_detail, provider_row


def test_gauge_is_half_full_at_score_50():
    report = EnrichmentReport(ioc="1.2.3.4", ioc_type=IOCType.IP, threat_score=50, risk_level=RiskLevel.MEDIUM)
    values = gauge(report)
    assert values["offset"] == pytest.approx(values["length"] / 2, rel=1e-3)
    assert values["unknown"] is False


def test_gauge_is_empty_for_unknown_risk():
    report = EnrichmentReport(ioc="1.2.3.4", ioc_type=IOCType.IP, risk_level=RiskLevel.UNKNOWN)
    assert gauge(report)["unknown"] is True


def test_coverage_counts_ok_disabled_and_failed_sources():
    rows = [
        provider_row(ProviderResult(provider="virustotal", success=True, normalized={"malicious": 1, "total_engines": 2})),
        provider_row(ProviderResult(provider="otx", success=False, error=DISABLED_ERROR)),
        provider_row(ProviderResult(provider="shodan", success=False, error="HTTP 429")),
    ]
    result = coverage(rows)
    assert result["answered"] == 1
    assert result["total"] == 3
    assert [segment["state"] for segment in result["segments"]] == ["ok", "off", "fail"]


def test_graph_places_related_items_around_the_center():
    report = EnrichmentReport(
        ioc="8.8.8.8",
        ioc_type=IOCType.IP,
        geo={"isp": "Google LLC"},
        related={"nameservers": ["ns1.example.com"]},
    )
    result = graph(report)
    assert result is not None
    assert len(result["nodes"]) == 2
    assert {node["kind"] for node in result["nodes"]} == {"isp", "ns"}


def test_graph_is_none_without_related_items():
    assert graph(EnrichmentReport(ioc="1.2.3.4", ioc_type=IOCType.IP)) is None


def test_provider_detail_reads_virustotal_numbers():
    result = ProviderResult(provider="virustotal", success=True, normalized={"malicious": 3, "total_engines": 70})
    assert provider_detail(result) == "3 / 70 motor zararlı dedi"
