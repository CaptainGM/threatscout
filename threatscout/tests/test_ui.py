from fastapi.testclient import TestClient

from threatscout import api


def test_login_page_shows_when_password_is_set(monkeypatch):
    monkeypatch.setattr(api.settings, "web_password", "gizli")
    client = TestClient(api.app)
    response = client.get("/login")
    assert response.status_code == 200
    assert "Yönetici girişi" in response.text
    assert 'id="intro"' in response.text


def test_theme_file_is_served():
    client = TestClient(api.app)
    response = client.get("/static/theme.css")
    assert response.status_code == 200
    assert "--accent" in response.text


def test_home_page_has_intro_and_no_ai_claim(make_engine, monkeypatch):
    monkeypatch.setattr(api, "engine", make_engine())
    client = TestClient(api.app)
    response = client.get("/")
    assert response.status_code == 200
    assert 'id="intro"' in response.text
    assert "Yapay Zeka" not in response.text
