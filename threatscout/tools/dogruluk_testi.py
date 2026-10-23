"""ThreatScout sonuçlarının doğruluğunu bilindik ve bilinmeyen değerlerle dener.

Kullanım (threatscout klasöründe, sanal ortam açıkken):
    python tools/dogruluk_testi.py cikti.json

Her değer için gerçek API'ler sorgulanır. Geçmişe kayıt yazılmaz.
VirusTotal ücretsiz planı dakikada 4 istek kabul eder, bu yüzden her değer
arasında kısa bir bekleme yapılır.
"""

import asyncio
import json
import pathlib
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from threatscout.config import Settings  # noqa: E402
from threatscout.engine import ThreatScoutEngine  # noqa: E402
from threatscout.models import detect_ioc_type  # noqa: E402

# (değer, beklenen grup, açıklama)
# iyi: temiz çıkmalı | kotu: yakalanmalı | supheli: riskli ama saldırı kanıtı değil
# bilinmeyen: kaynakların bilmediği değer, dürüst sonuç "yetersiz veri" olmalı
SAMPLES = [
    ("8.8.8.8", "iyi", "Google DNS"),
    ("1.1.1.1", "iyi", "Cloudflare DNS"),
    ("google.com", "iyi", "bilinen büyük site"),
    ("github.com", "iyi", "bilinen büyük site"),
    ("wikipedia.org", "iyi", "bilinen site"),
    ("microsoft.com", "iyi", "bilinen site"),
    ("example.com", "iyi", "IANA örnek alan adı"),
    ("https://www.google.com/", "iyi", "bilinen URL"),
    ("44d88612fea8a8f36de82e1278abb02f", "kotu", "EICAR test dosyası (MD5)"),
    ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "kotu", "EICAR test dosyası (SHA256)"),
    ("24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c", "kotu", "WannaCry örnek dosyası (SHA256)"),
    ("malware.wicar.org", "kotu", "bilerek zararlı bırakan test sitesi"),
    ("185.220.101.5", "supheli", "Tor çıkış düğümü"),
    ("bilinmeyen-test-alani-93k2.example", "bilinmeyen", "var olmayan alan adı"),
    ("203.0.113.10", "bilinmeyen", "belgeleme IP aralığı, kimse kullanmıyor"),
    ("ornek-kucuk-site-7x2q.com", "bilinmeyen", "büyük ihtimalle kayıtsız alan adı"),
]

PAUSE_SECONDS = 16


async def run(output_path: str) -> None:
    temp_dir = pathlib.Path(tempfile.mkdtemp(prefix="dogruluk-"))
    settings = Settings(
        sqlite_path=str(temp_dir / "app.db"),
        sqlite_cache_path=str(temp_dir / "cache.db"),
    )
    engine = ThreatScoutEngine(settings=settings)
    rows = []
    try:
        for index, (value, group, note) in enumerate(SAMPLES, start=1):
            started = time.perf_counter()
            report = await engine.enrich(
                value,
                ioc_type=detect_ioc_type(value),
                use_cache=False,
                persist=False,
                notify=False,
            )
            sources = [
                {"name": p.provider, "ok": p.success, "error": p.error}
                for p in report.providers
            ]
            rows.append({
                "value": value,
                "group": group,
                "note": note,
                "type": report.ioc_type.value,
                "risk": report.risk_level.value,
                "score": report.threat_score,
                "answered": sum(1 for p in report.providers if p.success),
                "total": len(report.providers),
                "sources": sources,
                "seconds": round(time.perf_counter() - started, 1),
            })
            pathlib.Path(output_path).write_text(
                json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            print(f"[{index}/{len(SAMPLES)}] {value} -> {report.risk_level.value} ({report.threat_score})", flush=True)
            if index < len(SAMPLES):
                await asyncio.sleep(PAUSE_SECONDS)
    finally:
        await engine.close()
    print("bitti", flush=True)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("Kullanım: python tools/dogruluk_testi.py cikti.json")
    asyncio.run(run(sys.argv[1]))
