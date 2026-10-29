# ThreatScout doğruluk raporu

Son güncelleme: 29 Ekim 2026

## Ne test edildi?

16 değer, dört gruba ayrıldı:

- **İyi (8):** bilinen büyük siteler ve Google, Cloudflare DNS sunucuları. Temiz çıkması bekleniyor.
- **Kötü (4):** EICAR test dosyası (iki hash), WannaCry örnek dosyasının hash'i ve bilerek zararlı bırakan test sitesi. Yakalanması bekleniyor.
- **Şüpheli (1):** Tor çıkış düğümü olan bir IP adresi. Riskli görünmesi bekleniyor.
- **Bilinmeyen (3):** kimsenin bilmediği ya da belgeleme için ayrılmış değerler. Dürüst cevap "yetersiz veri" olmalı.

Test `threatscout/tools/dogruluk_testi.py` ile yapıldı. Sonuçlar geçmişe kaydedilmez. Ücretsiz VirusTotal planı dakikada 4 istek kabul ettiği için değerler arasında 16 saniye bekleniyor.

## Çalıştırmalar

1. **22 Ekim, 22:35:** Eski VirusTotal kuralıyla. Tek bir motorun zararlı demesi puana yansıyordu. google.com düşük çıktı.
2. **22 Ekim, 22:42:** Yeni VirusTotal kuralıyla (en az 2 motor, her motor 3 puan).
3. **29 Ekim:** OTX ve URLhaus anahtarları eklendikten sonra. Yeni hatalar çıktı (aşağıda).
4. **29 Ekim, son çalıştırma:** Üçüncü çalıştırmadaki hatalar düzeltildikten sonra.

Üçüncü çalıştırmada görülen hata şuydu: OTX'in "rapor yok" cevabı ve URLhaus'un "listede yok" cevabı puana "temiz" olarak giriyordu. OTX'in alan adlarındaki rapor sayısı ve Shodan'ın port bilgisi de çok sayıda sitenin ortak sunucusundan geldiği için yanıltıcı puan veriyordu.

Yapılan düzeltmeler:

- "Rapor yok" ve "listede yok" cevapları temiz kanıtı sayılmıyor, puana girmiyor.
- Alan adlarında ve URL'lerde OTX rapor sayısı ile Shodan port bilgisi puana girmiyor. Sonuç kartında yalnızca bilgi olarak gösteriliyor.
- Alan adında URLhaus "listede" dese de VirusTotal zararlı bulmadıysa bu sonuç puana girmiyor.
- Temiz sonuç yalnızca bir veya iki kaynağın puanına dayanıyorsa sonuç kartında uyarı çıkıyor.

## Sonuçlar

| Değer | Beklenen | 2. çalıştırma (22 Ekim) | 3. çalıştırma (anahtarlar eklendi) | Son çalıştırma |
|---|---|---|---|---|
| 8.8.8.8 | temiz | Temiz (0) | Temiz (0) | Temiz (0) |
| 1.1.1.1 | temiz | Temiz (0) | Temiz (0) | Temiz (0) |
| google.com | temiz | Temiz (0) | Temiz (0) | Temiz (0) |
| github.com | temiz | Temiz (0) | Düşük (27.7) | Temiz (0) |
| wikipedia.org | temiz | Temiz (0) | Düşük (23.1) | Temiz (0) |
| microsoft.com | temiz | Temiz (0) | Temiz (0) | Temiz (0) |
| example.com | temiz | Temiz (0) | Orta (50.8) | Temiz (0) |
| https://www.google.com/ | temiz | Temiz (0) | Düşük (14.3) | Temiz (0) |
| EICAR (MD5) | kötü | Kritik (100) | Yüksek (72.2) | Kritik (100) |
| EICAR (SHA256) | kötü | Kritik (100) | Yüksek (72.2) | Kritik (100) |
| WannaCry (SHA256) | kötü | Kritik (100) | Kritik (97.2) | Kritik (97.2) |
| malware.wicar.org | kötü | Orta (57.0) | Orta (54.0) | Yüksek (70.2) |
| 185.220.101.5 | şüpheli | Orta (54.8) | Yüksek (68.8) | Yüksek (73.3) |
| bilinmeyen-test-alani-93k2.example | bilinmeyen | Yetersiz veri | Temiz (0) | Yetersiz veri |
| 203.0.113.10 | bilinmeyen | Temiz (0), 3/8 kaynak | Temiz (0), 3/8 kaynak | Temiz (0), yalnızca 2 kaynak puanladı |
| ornek-kucuk-site-7x2q.com | bilinmeyen | Temiz (0), 1/6 kaynak | Temiz (0) | Temiz (0), yalnızca VirusTotal puanladı |

## Özet

- Bilinen 8 iyi değerin hepsi temiz çıktı.
- Bilinen 3 kötü dosya kritik çıktı.
- Test sitesi (malware.wicar.org) yüksek çıktı. Bu bir test sitesi olduğu için kabul edilebilir bir sonuç.
- Tor düğümü yüksek çıktı.
- Bilinmeyen alan adı "yetersiz veri" dedi. Doğru cevap bu.
- Bilinmeyen IP ve ornek-kucuk-site-7x2q.com "temiz" dedi. Ama bu sonuçlar yalnızca bir veya iki kaynağa dayanıyor. Kartta bu uyarı çıkıyor.

## Zayıf taraflar

- **Alan adlarında temiz sonuç yalnızca VirusTotal'e dayanıyor.** URLhaus ve OTX alan adlarında puan vermiyor. Shodan da alan adlarında puan vermiyor. VirusTotal'in kaçırdığı bir site bu sistemde de temiz görünebilir.
- **Kaynak sayısı az.** Ücretsiz anahtarlarla çoğu değerde kaynakların yalnızca bir kısmı yanıt veriyor. GreyNoise anahtarı henüz yok.
- **Shodan ücretsiz planda alan adı sorgularına izin vermiyor (403).** Uygulama bunu artık açıkça yazıyor. IP sorgularında da bazen aynı hata çıkıyor.
- **Puanlar zamanla değişiyor.** 185.220.101.5 için 22 Ekim'de 54.8 (orta) çıkmıştı. Şimdi 73.3 (yüksek) çıkıyor.
- **Test seti küçük.** 16 değer var. Bu bir istatistik ölçümü değil, bir anlık görüntü.
- **Belgeleme adresi ve .example alan adı gerçek dünyada kullanılmaz.** 203.0.113.10 ve bilinmeyen-test-alani-93k2.example bu yüzden test setinde. İleride gerçek ama kayıtlı değerlerle değiştirilmeli.

## Testi tekrar çalıştırmak

```
cd threatscout
.venv\Scripts\activate
python tools/dogruluk_testi.py sonuc.json
```

Yaklaşık 5 dakika sürer. Her değerin sonucu `sonuc.json` dosyasına yazılır.
