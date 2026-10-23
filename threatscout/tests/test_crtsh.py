import httpx

from threatscout.models import IOCType
from threatscout.providers import CrtShProvider, _cert_summary

CERTS = [
    {
        "name_value": "example.com\nwww.example.com",
        "not_before": "2019-03-01T00:00:00",
        "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
    },
    {
        "name_value": "*.example.com",
        "not_before": "2024-05-01T00:00:00",
        "issuer_name": "C=US, O=DigiCert Inc, CN=DigiCert",
    },
    {
        "name_value": "other.net",
        "not_before": "2020-01-01T00:00:00",
        "issuer_name": "C=US, O=Other CA",
    },
]


def test_summary_counts_names_under_the_domain_only():
    summary = _cert_summary("example.com", CERTS)
    assert summary["cert_count"] == 3
    # www.example.com, example.com (yıldızlı kayıt aynı alan adını verir); other.net sayılmaz
    assert summary["subdomain_count"] == 2
    assert summary["first_seen"] == "2019-03-01"
    assert summary["issuer"] == "C=US, O=DigiCert Inc, CN=DigiCert"


def test_summary_for_a_domain_without_certificates():
    summary = _cert_summary("example.com", [])
    assert summary["cert_count"] == 0
    assert summary["first_seen"] == ""


def test_crtsh_supports_domains_and_urls_only():
    provider = CrtShProvider("")
    assert provider.enabled is True
    assert provider.supports(IOCType.DOMAIN)
    assert provider.supports(IOCType.URL)
    assert not provider.supports(IOCType.IP)


async def test_crtsh_query_asks_for_subdomains_in_json():
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        return httpx.Response(200, json=CERTS)

    provider = CrtShProvider("")
    provider._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    result = await provider.analyze("example.com", IOCType.DOMAIN)
    await provider.close()

    assert "q=%25.example.com" in seen["url"]
    assert "output=json" in seen["url"]
    assert result.success is True
    assert result.normalized["cert_count"] == 3
