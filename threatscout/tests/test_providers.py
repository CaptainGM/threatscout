import httpx

from threatscout.models import IOCType
from threatscout.providers import OTXProvider, URLhausProvider, WhoisProvider, _http_message


def test_urlhaus_needs_key():
    # URLhaus artik anahtar istiyor (anahtarsiz 401 hatasi aldik)
    assert URLhausProvider("").enabled is False
    assert URLhausProvider("anahtar").enabled is True


def test_rate_limit_message_is_clear():
    assert "limiti" in _http_message(429)


def test_whois_registration_date():
    raw = {"events": [{"eventAction": "registration", "eventDate": "2010-05-01T10:00:00Z"}]}
    assert WhoisProvider("").normalize(raw, IOCType.DOMAIN)["created"] == "2010-05-01"


async def test_otx_url_is_encoded():
    # URL icindeki / ve ? karakterleri istek adresini bozmamali
    seen = {}

    def handler(request):
        seen["path"] = request.url.raw_path.decode()
        return httpx.Response(200, json={})

    provider = OTXProvider("anahtar")
    provider._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    await provider.analyze_url("https://example.com/a?b=1")
    await provider.close()
    assert "/indicators/url/https%3A%2F%2Fexample.com%2Fa%3Fb%3D1/general" in seen["path"]
