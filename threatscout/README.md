# ThreatScout (uygulama klasörü)

Bu klasörde programın asıl kodu var. Kurulum ve kullanım için ana klasördeki `README.md` dosyasına bak.

Kısa notlar:

- Testleri çalıştırmak için sanal ortamı açıp `python -m pytest` yaz.
- Web sunucusunu elle başlatmak için: `python -m uvicorn threatscout.api:app --host 127.0.0.1 --port 8000`
- `threatscout/` klasörü programın kendisi (api, cli, engine, providers gibi dosyalar), `templates/` web sayfaları, `tests/` ise testler.
