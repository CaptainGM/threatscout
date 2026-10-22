# ThreatScout

ThreatScout, şüpheli bir IP adresini, site adını (domain), linki veya dosya hash'ini birkaç güvenlik servisinde aynı anda kontrol eden küçük bir programdır.

Girdiğin değerin türünü kendisi tanır (IP, domain, URL, hash veya e-posta). Sonra VirusTotal, AbuseIPDB, Shodan gibi servislere sorar ve 0-100 arası bir risk puanı verir.

## Neler yapabilir?

- Tek bir değeri web sayfasından ya da terminalden taramak
- Listeyi toplu taramak (en fazla 50 satır)
- Geçmiş taramaları veritabanında saklamak
- Sonucu PDF, HTML ya da JSON olarak kaydetmek
- Kendi programlarından kullanmak için bir REST API (`/docs` adresinde açıklaması var)

## Kurulum

1. Bilgisayarında Python 3.11 veya daha yeni bir sürüm olsun.
2. `threatscout` klasörünün içinde sanal ortam oluştur ve kütüphaneleri kur:

   ```
   cd threatscout
   python -m venv .venv
   .venv\Scripts\activate
   pip install -e ".[dev]"
   ```

3. `threatscout` klasöründeki `.env.example` dosyasının kopyasını al ve adını `.env` yap.
4. `.env` dosyasını açıp kendi API anahtarlarını yaz. Anahtarı olmayan servis kapalı kalır, bu bir hata değil.

Anahtarları VirusTotal, AbuseIPDB, Shodan, AlienVault OTX ve GreyNoise sitelerinden ücretsiz alabilirsin. URLhaus için abuse.ch anahtarı gerekebilir.

## Çalıştırma

- En kolayı: ana klasördeki `baslat.bat` dosyasına çift tıkla. Tarayıcı kendiliğinden açılır: http://127.0.0.1:8000
- Terminalden taramak istersen:

  ```
  threatscout scan 8.8.8.8
  threatscout scan ornek.com --format html -o rapor.html
  threatscout batch liste.txt -d reports
  ```

## Güvenlik notları

- `.env` dosyası API anahtarlarını taşır. Bu dosyayı kimseyle paylaşma ve GitHub'a yükleme. `.gitignore` dosyası bunu zaten engelliyor.
- `WEB_PASSWORD` boşsa web sayfası parolasız açılır. Bu yüzden programı sadece kendi bilgisayarında kullan.

## Bilinen eksikler

- Ücretsiz API'lerin dakikalık ve günlük limitleri var. Çok fazla tarama yaparsan "limit doldu" hatası görebilirsin.
- PDF raporda Türkçe harflerin bazıları (ş, ğ, ı, İ) benzer harflerle yazılır.
