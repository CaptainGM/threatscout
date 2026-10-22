from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.middleware.sessions import SessionMiddleware

from threatscout.config import get_settings
from threatscout.engine import ThreatScoutEngine
from threatscout.models import EnrichmentReport, IOCType, detect_ioc_type
from threatscout.pdf import render_pdf
from threatscout.report import RISK_COLORS, breakdown_rows, render_html

settings = get_settings()
limiter = Limiter(key_func=get_remote_address, default_limits=[settings.rate_limit])
engine: ThreatScoutEngine | None = None
TEMPLATE_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATE_DIR))
templates.env.globals["risk_colors"] = {k.value: v for k, v in RISK_COLORS.items()}
templates.env.globals["auth_required"] = bool(settings.web_password)

# Kaynaklarin adi ve kisa aciklamasi (ana sayfada gosterilir)
PROVIDER_INFO = {
    "virustotal": ("VirusTotal", "Dosya, URL ve domain için antivirüs motorları"),
    "abuseipdb": ("AbuseIPDB", "IP adresi için şikayet geçmişi"),
    "shodan": ("Shodan", "Açık portlar ve servisler"),
    "otx": ("AlienVault OTX", "Topluluk tehdit raporları"),
    "greynoise": ("GreyNoise", "İnternet tarama trafiği ve bilinen tarayıcılar"),
    "urlhaus": ("URLhaus", "Zararlı bağlantı listesi"),
    "misp": ("MISP", "Kendi MISP sunucunuz (isteğe bağlı)"),
    "whois": ("WHOIS / RDAP", "Alan adı ve IP sahiplik bilgisi"),
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    global engine
    engine = ThreatScoutEngine()
    yield
    if engine:
        await engine.close()


app = FastAPI(title="ThreatScout", version="1.0.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")
app.add_middleware(SessionMiddleware, secret_key=settings.app_secret, session_cookie="threatscout")
app.state.limiter = limiter
def rate_limited(request: Request, exc: RateLimitExceeded):
    text = "Cok hizli istek gonderdiniz. Biraz bekleyip tekrar deneyin."
    if request.url.path.startswith("/api/"):
        return JSONResponse({"detail": text}, status_code=429)
    return HTMLResponse(f'<div class="error">{text}</div>', status_code=429)


app.add_exception_handler(RateLimitExceeded, rate_limited)


@app.middleware("http")
async def block_cross_site_posts(request: Request, call_next):
    # Baska bir sitenin tarayicidan gonderdigi POST isteklerini engelle
    origin = request.headers.get("origin")
    if request.method == "POST" and origin:
        if urlparse(origin).netloc != request.headers.get("host"):
            return JSONResponse({"detail": "Bu istek bu siteden gelmiyor"}, status_code=403)
    return await call_next(request)


def _engine() -> ThreatScoutEngine:
    if not engine:
        raise HTTPException(503, "Motor hazir degil")
    return engine


def web_unlocked(request: Request) -> bool:
    if not settings.web_password:
        return True
    return bool(request.session.get("auth"))


def api_unlocked(request: Request) -> bool:
    if request.session.get("auth"):
        return True
    key = request.headers.get("X-API-Key")
    if settings.app_api_key and key == settings.app_api_key.strip():
        return True
    if engine is None:
        return False
    return engine.store.valid_api_key(key)


def require_web(request: Request) -> None:
    if not web_unlocked(request):
        raise HTTPException(status_code=302, headers={"Location": "/login"})


def require_api(request: Request) -> None:
    if not api_unlocked(request):
        raise HTTPException(401, "Gecerli X-API-Key gerekli")


@app.exception_handler(HTTPException)
async def http_exc_handler(request: Request, exc: HTTPException):
    if exc.status_code == 302 and exc.headers and exc.headers.get("Location"):
        return RedirectResponse(exc.headers["Location"], status_code=302)
    if request.url.path.startswith("/api/"):
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = ""):
    if not settings.web_password or web_unlocked(request):
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse(request, "login.html", {"error": error})


@app.post("/login")
async def login(request: Request, password: str = Form(...)):
    if not settings.web_password:
        # Parola yoksa giris gerekmez; oturum da acilmaz
        return RedirectResponse("/", status_code=302)
    if password != settings.web_password:
        return templates.TemplateResponse(
            request, "login.html", {"error": "Hatali parola"}, status_code=401
        )
    request.session["auth"] = True
    return RedirectResponse("/", status_code=302)


@app.post("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login" if settings.web_password else "/", status_code=302)


@app.get("/", response_class=HTMLResponse)
async def home(request: Request, _: None = Depends(require_web)):
    eng = _engine()
    scans = eng.store.list_scans(limit=8)
    providers = []
    for p in eng.providers:
        label, desc = PROVIDER_INFO.get(p.name, (p.name, ""))
        providers.append({"label": label, "desc": desc, "enabled": p.enabled})
    return templates.TemplateResponse(
        request,
        "index.html",
        {"scans": scans, "providers": providers, "auth_required": bool(settings.web_password)},
    )


@app.post("/scan", response_class=HTMLResponse)
@limiter.limit(settings.rate_limit)
async def web_scan(
    request: Request,
    ioc: str = Form(...),
    no_cache: bool = Form(False),
    _: None = Depends(require_web),
):
    eng = _engine()
    ioc = ioc.strip()
    ioc_type = detect_ioc_type(ioc)
    if ioc_type == IOCType.UNKNOWN:
        return templates.TemplateResponse(
            request,
            "result.html",
            {"error": "Gecersiz IOC", "report": None},
            status_code=400,
        )
    report = await eng.enrich(ioc, ioc_type=ioc_type, use_cache=not no_cache)
    return templates.TemplateResponse(
        request,
        "result.html",
        {
            "report": report,
            "breakdown_rows": breakdown_rows(report),
            "risk_color": RISK_COLORS.get(report.risk_level, "#6b7280"),
            "error": None,
        },
    )


@app.post("/batch", response_class=HTMLResponse)
@limiter.limit(settings.rate_limit)
async def web_batch(
    request: Request,
    iocs: str = Form(...),
    no_cache: bool = Form(False),
    _: None = Depends(require_web),
):
    eng = _engine()
    items = [
        line.strip()
        for line in iocs.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    reports: list[EnrichmentReport] = []
    for item in items[:50]:
        kind = detect_ioc_type(item)
        if kind == IOCType.UNKNOWN:
            continue
        reports.append(await eng.enrich(item, ioc_type=kind, use_cache=not no_cache))
    return templates.TemplateResponse(request, "batch_result.html", {"reports": reports})


@app.get("/history", response_class=HTMLResponse)
async def history_page(request: Request, q: str = "", _: None = Depends(require_web)):
    scans = _engine().store.list_scans(limit=100, q=q)
    return templates.TemplateResponse(request, "history.html", {"scans": scans, "q": q})


@app.get("/history/{scan_id}", response_class=HTMLResponse)
async def history_detail(request: Request, scan_id: int, _: None = Depends(require_web)):
    data = _engine().store.get_scan(scan_id)
    if not data:
        raise HTTPException(404, "Kayit yok")
    report = EnrichmentReport.model_validate(data)
    return templates.TemplateResponse(
        request,
        "history_detail.html",
        {
            "report": report,
            "breakdown_rows": breakdown_rows(report),
            "risk_color": RISK_COLORS.get(report.risk_level, "#6b7280"),
        },
    )


@app.get("/history/{scan_id}/pdf")
async def history_pdf(scan_id: int, _: None = Depends(require_web)):
    data = _engine().store.get_scan(scan_id)
    if not data:
        raise HTTPException(404, "Kayit yok")
    report = EnrichmentReport.model_validate(data)
    return Response(
        content=render_pdf(report),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="threatscout-{scan_id}.pdf"'},
    )


@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request, flash: str = "", _: None = Depends(require_web)):
    store = _engine().store
    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "keys": store.list_api_keys(),
            "webhooks": store.list_webhooks(),
            "deliveries": store.recent_deliveries(),
            "new_key": None,
            "flash": flash,
            "app_api_configured": bool(settings.app_api_key),
        },
    )


@app.post("/settings/keys")
async def create_key(request: Request, name: str = Form(...), _: None = Depends(require_web)):
    raw = _engine().store.create_api_key(name.strip() or "default")
    store = _engine().store
    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "keys": store.list_api_keys(),
            "webhooks": store.list_webhooks(),
            "deliveries": store.recent_deliveries(),
            "new_key": raw,
            "flash": "Yeni anahtar olusturuldu. Bir daha gosterilmez.",
            "app_api_configured": bool(settings.app_api_key),
        },
    )


@app.post("/settings/keys/{key_id}/delete")
async def delete_key(key_id: int, _: None = Depends(require_web)):
    _engine().store.delete_api_key(key_id)
    return RedirectResponse("/settings", status_code=302)


@app.post("/settings/webhooks")
async def create_webhook(
    name: str = Form(...),
    kind: str = Form(...),
    url: str = Form(...),
    token: str = Form(""),
    _: None = Depends(require_web),
):
    _engine().store.add_webhook(name.strip(), kind.strip().lower(), url.strip(), token.strip())
    return RedirectResponse("/settings", status_code=302)


@app.post("/settings/webhooks/{webhook_id}/toggle")
async def toggle_webhook(webhook_id: int, enabled: int = Form(...), _: None = Depends(require_web)):
    _engine().store.toggle_webhook(webhook_id, bool(enabled))
    return RedirectResponse("/settings", status_code=302)


@app.post("/settings/webhooks/{webhook_id}/delete")
async def delete_webhook(webhook_id: int, _: None = Depends(require_web)):
    _engine().store.delete_webhook(webhook_id)
    return RedirectResponse("/settings", status_code=302)


@app.get("/api/v1/enrich/ip/{ip}")
@limiter.limit(settings.rate_limit)
async def enrich_ip(request: Request, ip: str, use_cache: bool = True, _: None = Depends(require_api)):
    if detect_ioc_type(ip) != IOCType.IP:
        raise HTTPException(400, "Gecersiz IP adresi")
    return (await _engine().enrich(ip, ioc_type=IOCType.IP, use_cache=use_cache)).to_dict()


@app.get("/api/v1/enrich/{ioc:path}")
@limiter.limit(settings.rate_limit)
async def enrich(request: Request, ioc: str, use_cache: bool = True, _: None = Depends(require_api)):
    ioc_type = detect_ioc_type(ioc)
    if ioc_type == IOCType.UNKNOWN:
        raise HTTPException(400, "Gecersiz IOC")
    return (await _engine().enrich(ioc, ioc_type=ioc_type, use_cache=use_cache)).to_dict()


@app.get("/api/v1/history")
async def api_history(q: str = "", limit: int = 50, _: None = Depends(require_api)):
    return _engine().store.list_scans(limit=min(limit, 200), q=q)


@app.get("/api/v1/history/{scan_id}")
async def api_history_detail(scan_id: int, _: None = Depends(require_api)):
    data = _engine().store.get_scan(scan_id)
    if not data:
        raise HTTPException(404, "Kayit yok")
    return data


@app.get("/api/v1/history/{scan_id}/pdf")
async def api_history_pdf(scan_id: int, _: None = Depends(require_api)):
    data = _engine().store.get_scan(scan_id)
    if not data:
        raise HTTPException(404, "Kayit yok")
    report = EnrichmentReport.model_validate(data)
    return Response(
        content=render_pdf(report),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="threatscout-{scan_id}.pdf"'},
    )


@app.get("/api/v1/report/html/{ioc:path}", response_class=HTMLResponse)
@limiter.limit(settings.rate_limit)
async def html_report(request: Request, ioc: str, use_cache: bool = True, _: None = Depends(require_api)):
    report = await _engine().enrich(ioc, use_cache=use_cache)
    return HTMLResponse(render_html(report))


def main():
    import uvicorn
    uvicorn.run("threatscout.api:app", host=settings.api_host, port=settings.api_port, reload=False)


if __name__ == "__main__":
    main()
