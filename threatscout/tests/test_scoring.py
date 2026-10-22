from threatscout.engine import RiskScorer
from threatscout.models import EnrichmentReport, IOCType, ProviderResult, RiskLevel


def test_no_data_means_unknown():
    report = EnrichmentReport(
        ioc="1.2.3.4",
        ioc_type=IOCType.IP,
        providers=[ProviderResult(provider="virustotal", success=False, error="x")],
    )
    result = RiskScorer().enrich_report(report)
    assert result.risk_level == RiskLevel.UNKNOWN


def test_email_without_scoring_sources_is_unknown():
    # E-posta icin skor veren kaynak (OTX, MISP) yoksa sonuc temiz degil, bilinmiyor olmali
    report = EnrichmentReport(
        ioc="user@example.com",
        ioc_type=IOCType.EMAIL,
        providers=[ProviderResult(provider="whois", success=True, normalized={"emails": []})],
    )
    result = RiskScorer().enrich_report(report)
    assert result.risk_level == RiskLevel.UNKNOWN


async def test_invalid_input_is_unknown(make_engine):
    report = await make_engine().enrich("bu bir ioc degil")
    assert report.risk_level == RiskLevel.UNKNOWN
