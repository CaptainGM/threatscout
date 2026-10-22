# ThreatScout

Şüpheli IP, site (domain), link ve dosya hash'lerini tarayan basit ve hızlı bir siber istihbarat aracı. 

Bir IP veya link gördüğünde "bu virüslü mü, hacker sunucusu mu?" diye merak ettiğinde buraya yapıştırıyorsun; VirusTotal, Shodan, AbuseIPDB gibi yerlere sorup sana 0-100 arası bir tehlike puanı ve özet rapor veriyor.

---

## Ne İşe Yarar? (Kısaca)

- **IP Sorgulama:** IP hangi ülkede, kime ait, açık portu var mı, daha önce saldırı yapmış mı?
- **Domain / URL Sorgulama:** Bu site dolandırıcı (phishing) sitesi mi, virüs yayıyor mu?
- **Hash Sorgulama:** İndirdiğin bir dosyanın özeti (MD5/SHA256) bilinen bir virüsle eşleşiyor mu?
- **Raporlama:** İstersen sonucu PDF veya HTML olarak indirebilirsin.

---

## Nasıl Çalıştırılır?

En kolayı: Proje klasöründeki `baslat.bat` dosyasına çift tıkla, otomatik tarayıcıyı açar.

Manuel çalıştırmak istersen:

```bash
# Klasöre gir
cd threatscout

# Sanal ortamı aç (varsa)
.venv\Scripts\activate

# Başlat
python -m uvicorn threatscout.api:app --host 127.0.0.1 --port 8000
```

Tarayıcıdan: `http://127.0.0.1:8000`

---

## API Anahtarları (.env)

Bazı servisler (VirusTotal, AbuseIPDB, Shodan) ücretsiz API anahtarı istiyor. `.env` dosyasına anahtarlarını yapıştırabilirsin:

```env
VIRUSTOTAL_API_KEY=senin_anahtarin
ABUSEIPDB_API_KEY=senin_anahtarin
SHODAN_API_KEY=senin_anahtarin
```

Anahtarın yoksa da WHOIS ve URLhaus gibi servisler anahtarsız yine çalışır.

---

## Terminalden Tarama (CLI)

Web arayüzü yerine terminalden hızlıca bakmak istersen:

```bash
threatscout scan 8.8.8.8
threatscout scan zararlisite.com --format html -o rapor.html
threatscout batch ioc-listesi.txt -d reports
```
