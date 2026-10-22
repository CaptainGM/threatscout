from fastapi.testclient import TestClient

from threatscout import api


def test_login_without_password_does_not_open_session():
    # Parola bossa /login oturum acmamali, API hala anahtar istemeli
    client = TestClient(api.app)
    client.post("/login", data={"password": "herhangi"}, follow_redirects=False)
    assert client.get("/api/v1/history").status_code == 401


def test_api_key_must_be_in_header(make_engine, monkeypatch):
    monkeypatch.setattr(api, "engine", make_engine())
    monkeypatch.setattr(api.settings, "app_api_key", "test-key")
    client = TestClient(api.app)
    assert client.get("/api/v1/history?api_key=test-key").status_code == 401
    assert client.get("/api/v1/history", headers={"X-API-Key": "test-key"}).status_code == 200


def test_cross_site_post_is_blocked():
    client = TestClient(api.app)
    response = client.post("/logout", headers={"origin": "http://evil.example"})
    assert response.status_code == 403


def test_same_site_post_is_allowed():
    client = TestClient(api.app)
    response = client.post(
        "/logout", headers={"origin": "http://testserver"}, follow_redirects=False
    )
    assert response.status_code == 302


def test_ip_endpoint_rejects_bad_ip(make_engine, monkeypatch):
    monkeypatch.setattr(api, "engine", make_engine())
    monkeypatch.setattr(api.settings, "app_api_key", "test-key")
    client = TestClient(api.app)
    response = client.get("/api/v1/enrich/ip/bu-ip-degil", headers={"X-API-Key": "test-key"})
    assert response.status_code == 400
