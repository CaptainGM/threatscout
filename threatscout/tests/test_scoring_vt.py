import pytest

from threatscout.engine import RiskScorer
from threatscout.models import EnrichmentReport, IOCType, ProviderResult, RiskLevel


def vt_report(malicious: int, total: int = 90) -> EnrichmentReport:
    return EnrichmentReport(
        ioc="8.8.8.8",
        ioc_type=IOCType.IP,
        providers=[
            ProviderResult(
                provider="virustotal",
                success=True,
                normalized={"malicious": malicious, "total_engines": total},
            )
        ],
    )


def test_one_engine_alone_is_not_a_threat():
    result = RiskScorer().enrich_report(vt_report(1))
    assert result.threat_score == 0
    assert result.risk_level == RiskLevel.CLEAN


def test_two_engines_only_give_a_low_score():
    result = RiskScorer().enrich_report(vt_report(2))
    assert result.threat_score == pytest.approx(6)
    assert result.risk_level == RiskLevel.LOW


def test_fourteen_engines_are_medium():
    result = RiskScorer().enrich_report(vt_report(14))
    assert result.threat_score == pytest.approx(42)
    assert result.risk_level == RiskLevel.MEDIUM


def test_twenty_engines_are_high():
    result = RiskScorer().enrich_report(vt_report(20))
    assert result.threat_score == pytest.approx(60)
    assert result.risk_level == RiskLevel.HIGH


def test_many_engines_are_critical():
    result = RiskScorer().enrich_report(vt_report(60))
    assert result.threat_score == 100
    assert result.risk_level == RiskLevel.CRITICAL
