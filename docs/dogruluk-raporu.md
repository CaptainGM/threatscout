# ThreatScout doğruluk raporu

Tarih: 22 Ekim 2026

## Ne test edildi?

16 değer, dört gruba ayrıldı:

- **İyi (8):** bilinen büyük siteler ve Google/Cloudflare DNS. Temiz çıkması bekleniyor.
- **Kötü (4):** EICAR test dosyası (iki hash), WannaCry örnek dosyasının hash'i ve bilerek zararlı bırakan test sitesi. Yakalanması bekleniyor.
- **Şüpheli (1):** Tor çıkış düğümü olan bir IP adresi. Riskli görünmesi bekleniyor, ama saldırı kanıtı yok.
- **Bilinmeyen (3):** kimsenin bilmediği ya da belgeleme için ayrılmış değerler. Dürüst cevap "yetersiz veri" olmalı, "temiz" değil.

Test `threatscout/tools/dogruluk_testi.py` ile yapıldı. Sonuçlar geçmişe kaydedilmedi. VirusTotal ücretsiz planı dakikada 4 istek kabul ettiği için değerler arasında 16 saniye bekleniyor.

İki çalıştırma yapıldı:

1. **22:35 (eski VirusTotal kuralı):** VirusTotal'de tek bir motorun zararlı demesi bile puana yansıyordu.
2. **22:42 (yeni kural):** `ce4af37` commit'inden sonra. En az 2 motor gerekiyor, her motor 3 puan ekliyor.

## Sonuçlar

| Değer | Grup | 1. çalıştırma | 2. çalıştırma | Yorum |
|---|---|---|---|---|
| 8.8.8.8 | iyi | Temiz (0) | Temiz (0) | Doğru |
| 1.1.1.1 | iyi | Temiz (0) | Temiz (0) | Doğru |
| google.com | iyi | Düşük (1.1) | Temiz (0) | İlk çalıştırmada tek VirusTotal motoru yanlış alarm verdi. Kural düzeltildi. |
| github.com | iyi | Temiz (0) | Temiz (0) | Doğru |
| wikipedia.org | iyi | Temiz (0) | Temiz (0) | Doğru |
| microsoft.com | iyi | Temiz (0) | Temiz (0) | Doğru |
| example.com | iyi | Temiz (0) | Temiz (0) | Doğru |
| https://www.google.com/ | iyi | Temiz (0) | Temiz (0) | Doğru, ama yalnızca 1 kaynak yanıt verdi |
| EICAR (MD5) | kötü | Kritik (85.3) | Kritik (100) | Doğru |
| EICAR (SHA256) | kötü | Kritik (85.3) | Kritik (100) | Doğru |
| WannaCry (SHA256) | kötü | Kritik (90.7) | Kritik (100) | Doğru |
| malware.wicar.org | kötü | Düşük (20.7) | Orta (57.0) | İlk çalıştırmada düşük kalıyordu. Şimdi orta, ama yalnızca VirusTotal yanıt verdi. |
| 185.220.101.5 | şüpheli | Orta (45.6) | Orta (54.8) | Makul. Tor düğümleri sık raporlanır. |
| bilinmeyen-test-alani-93k2.example | bilinmeyen | Yetersiz veri | Yetersiz veri | Dürüst sonuç, ama sebebi farklı: VirusTotal bu değer için 400 hatası döndürdü (büyük ihtimalle `.example` uzantısı yüzünden). |
| 203.0.113.10 | bilinmeyen | Temiz (0), 3/8 kaynak | Temiz (0), 3/8 kaynak | Zayıf. Az kaynakla "temiz" dedi. Ekranda uyarı çıkıyor. |
| ornek-kucuk-site-7x2q.com | bilinmeyen | Yetersiz veri (VirusTotal bilmiyordu) | Temiz (0), 1/6 kaynak | Tutarsız. İkinci seferde VirusTotal bir kayıt döndürdü. Ekranda uyarı çıkıyor. |

## Özet

**İyi olan taraflar**

- Bilinen temiz değerlerin hepsi ikinci çalıştırmada temiz çıktı. İlk çalıştırmadaki tek yanlış alarm (google.com) düzeltildi.
- Bilinen üç kötü hash, iki çalıştırmada da kritik çıktı.
- Hiçbir kaynağın bilmediği değer için "temiz" denmedi. Bu bilinmeyen değerlerde sonuç "yetersiz veri" oldu.

**Zayıf taraflar**

- **Kaynak sayısı az.** Ücretsiz anahtarlarla çoğu değerde kaynaklardan yalnızca 1 ila 4'ü yanıt veriyor. OTX, GreyNoise, URLhaus ve MISP için anahtar yok. Bu yüzden çoğu sonuç aslında VirusTotal, AbuseIPDB ve WHOIS üzerinden çıkıyor.
- **Tek kaynaklı "temiz" sonuçlar güvenilir değil.** 203.0.113.10 ve ornek-kucuk-site-7x2q.com bunun örneği. Sonuç kartında artık "Yalnızca N kaynak veri döndürdü" uyarısı çıkıyor.
- **Shodan 403 hatası veriyor.** Alan adı sorgularının çoğunda bu hata çıktı. IP sorgularında genellikle çalışıyor, ama sonradan yapılan bir taramada 185.220.101.5 için de 403 döndü. Kota ya da ücretli plan sınırı olabilir, kesin nedenini bilmiyorum. Hata mesajı "anahtar geçersiz" gibi okunuyor, bu da yanıltıcı.
- **Sonuçlar zamanla değişebiliyor.** ornek-kucuk-site-7x2q.com iki çalıştırmada farklı sonuç verdi. Büyük ihtimalle bu, VirusTotal'in o an bildiklerinin bir yansıması. 185.220.101.5 için 22 Ekim'deki taramada 54.8 (orta) çıkmıştı. Sonradan yapılan taramada 68.0 (yüksek) çıktı. Bu sırada Shodan yanıt vermedi. Puanın bir kısmı bundan kaynaklanmış olabilir.

## Bu testin sınırları

- 16 değer ve iki çalıştırma var. Bu bir istatistik ölçümü değil, bir anlık görüntü.
- Yanlış alarm oranını ölçmek için yeterli temiz örnek yok. Sadece birkaç bilinen site test edildi.
- Testte kullanılan belgeleme adresi (203.0.113.10) ve `.example` alan adı gerçek dünyada kullanılmaz. Gelecekte bunların yerine gerçek ama kayıtlı değerler kullanılmalı.

## Ne yapılacak?

- OTX ve GreyNoise anahtarları eklenince testi yeniden çalıştırmak. Kaynak sayısı artınca "tek kaynak" uyarısının sıklığı da azalacak.
- Shodan 403 mesajını "bu sorgu için yetki yok, ücretli plan gerekebilir" diye açıklamak.
- Test kümesinden belgeleme adreslerini ve `.example` alan adını çıkarmak.

## Testi tekrar çalıştırmak

```
cd threatscout
.venv\Scripts\activate
python tools/dogruluk_testi.py sonuc.json
```

Yaklaşık 5 dakika sürer. Her değerin sonucu `sonuc.json` dosyasına yazılır.
