# Hafta 7 - Anlamsal arama modülü

## Uygulama

`mitre_final/search.py`, Sentence Transformer modelini yükleme, token sınırına
uygun parçalama, normalize embedding üretme, indeks kaydetme ve sorgu sıralama
işlemlerini içerir. Model CPU üzerinde çalıştırılır; aynı modelin kaydedilmiş
revizyonu sorgu sırasında da kullanılır. İndeks dosyalarının SHA-256 özetleri
yüklemede doğrulanır.

Her teknik için birden çok metin parçası olabilir. Kosinüs sıralamasından sonra
aynı teknik kimliği tekrarlanmaz; en iyi parçası sonuçta kanıt metni olarak
sunulur. Üst ve alt teknik bu sürümde ayrı kimliklerdir. Sonuçlar adaydır;
LLM gerekçelendirmesi ve kesin saldırı tespiti yapılmaz.

## Doğrulama durumu

**Gerçek modelle indeks ve dört sorgu demosu tamamlandı.**
697 kayıt 1.993 parçaya ayrıldı ve 384 boyutlu vektörlere dönüştürüldü.
Token sınırı 128; kaydedilen parçaların hiçbiri sınırı aşmıyor.
İndeks, demo çıktıları ve token kontrolü `evidence/` altındadır.

9 otomatik testin içinde veri filtreleme, kaynak özeti, yinelenen teknik,
kosinüs sıralama, parçaları tekilleştirme ve geçersiz vektör kontrolleri vardır.
Bu testlerdeki sentetik vektörler, gerçek embedding çalışması yerine geçmez.

## Gerçek demo sonuçları

| Olay | İncelenen aday | Gözlenen sıra |
|---|---|---|
| PowerShell ile betik yürütme, İngilizce | T1059.001 | 1 |
| PowerShell ile betik yürütme, Türkçe | T1059.001 | 1 |
| Yeniden başlatma sonrası zamanlanmış görev | T1053.005 | 2; üst teknik T1053 ilk sırada |
| LSASS belleğinden kimlik bilgisi | T1003.001 | 1 |

Bu dört örnek elle hazırlanmış gösterimlerdir. Bağımsız benchmark değildir;
buradan genel başarı yüzdesi, Recall@K veya MRR sonucu çıkarılmamıştır.

Model revizyonu, paket sürümleri ve boyutlar `evidence/index_manifest.json`;
gerçek sonuçlar `semantic_demo_en.json` ve `semantic_demo_tr.json` içindedir.
`examples/demo_queries.json` dosyasındaki `inspect_candidate`, elle seçilmiş
incelenecek adaydır. Gerçek model sırası ayrı demo çıktısından okunur.

## Sınırlılıklar

Çok dilli model seçimi Türkçe başarısı garantilemez. Uzun sorgular reddedilir;
kısa olay açıklamalarıyla başlanır. Benzerlik skoru güven olasılığı değildir.
Doğruluk, Recall@K ve MRR karşılaştırması 12–13. haftada hazırlanacak bağımsız
etiketli örnekler üzerinde yapılacaktır.
