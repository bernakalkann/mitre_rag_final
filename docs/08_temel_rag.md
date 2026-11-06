# Hafta 8 - Temel RAG akışı ve ilk uçtan uca demo

## Planın hedefi

Olay açıklamasından aday teknikleri bulmak ve temel yanıt akışını oluşturmak.
Bu aşama, 7. haftadaki anlamsal aramaya yerel modelle kısa açıklama üretimini
ekler. 11. haftada teknik kodunu, kaynağı ve açıklamayı gösteren ekran
tamamlanacaktır. BM25 ve hibrit arama henüz eklenmemiştir.

## Çalışan akış

1. Kullanıcı kısa bir güvenlik olayı açıklaması girer.
2. 7. haftada oluşturulan MiniLM indeksi aynı modelle sorgulanır.
3. İlk üç benzersiz tekniğin ilgili metin parçaları alınır.
4. Olay ve bu kaynaklar yerel Ollama üzerinden Qwen3:8b modeline verilir.
5. Model bir özet, kaynak kimliklerine bağlı eşleşmeler ve ek bilgi ihtiyacı üretir. Alıntıyı kaynaklardan çıkarılmış gerçek kısa metin seçeneklerinden seçer.
6. Kaynak kimlikleri ve metinden yapılan alıntılar kontrol edilir.
7. Teknik adı, ATT&CK kodu ve resmî bağlantı, modelden alınmak yerine indeksten eklenir.

Kaynakta olmayan alıntı, bilinmeyen kaynak kimliği, yinelenen eşleşme veya
adaylar dışında teknik kodu varsa yanıt başarılı çıktı olarak sunulmaz.
Bağlantı hatası, tamamlanmamış akış ve token sınırında kesilen yanıt da hata
olarak bildirilir. Hata halinde sahte bir açıklama veya önceki demo sonucu
döndürülmez.

## Model ve araçlar

| Görev | Kullanılan bileşen |
|---|---|
| Embedding | Sentence Transformers / paraphrase-multilingual-MiniLM-L12-v2 |
| Bilgi erişimi | NumPy ile normalize vektörlerin kosinüs benzerliği |
| Yanıt üretimi | Qwen3:8b |
| Yerel model servisi | Ollama / yalnızca yerel HTTP bağlantısı |
| Yanıt biçimi | JSON şeması, kısa Türkçe açıklama ve kaynak alıntısı |

Qwen3:8b bu ilk demo için bilgisayarda kurulu olan başlangıç modelidir.
Ollama modelin adı değil, modeli çalıştıran yerel servistir. Üretimde sıcaklık
0, bağlam sınırı 8.192 ve çıktı sınırı 1.200 token olarak ayarlanmıştır.
Uzun düşünme çıktısı kapalıdır. Modelin digest değeri ve Ollama sürümü gerçek
demo dosyalarına kaydedilir. Ücretli veya uzak LLM API'si kullanılmaz.

## Kurulum ve komutlar

Komutları repo kökünde, Python ortamı etkin durumdayken çalıştırın.
Temel Python paketleri `requirements.txt` içindedir. Ollama ayrıca kurulu ve
çalışır olmalıdır. `ollama list` çıktısında Qwen3:8b bulunmalıdır. Yoksa modeli
`ollama pull qwen3:8b` ile kurun; ilk indirme internet gerektirir.

```sh
python3.12 -m venv .venv
source .venv/bin/activate
export HF_HOME="$PWD/data/model_cache"
python -m pip install -r requirements.txt
python -m mitre_final download
python -m mitre_final prepare
python -m mitre_final index
python -m mitre_final rag "Saldırgan Windows bilgisayarda PowerShell kullanarak kötü amaçlı bir betik çalıştırdı." --offline --output evidence/week08_rag_demo_tr.json
```

Önceki haftanın indeksi ve model önbelleği varsa indirme, prepare ve index
adımlarını tekrarlamak gerekmez. `--offline`, embedding modelini yerel
önbellekten yükler; yerel Ollama servisinin yine çalışması gerekir.

İsteğe bağlı komut parametreleri: `--top-k`, `--llm-model`, `--ollama-url`,
`--timeout`, `--index` ve `--output`. Varsayılan olarak üç aday kullanılır.
Kaynak sayısı 1-10 ile sınırlandırılır. Model çağrısında otomatik tekrar yoktur.

## Doğrulama ve sınırlar

Gerçek uçtan uca çıktı: [Türkçe PowerShell demosu](../evidence/week08_rag_demo_tr.json).
Bu örnekte model T1059.001 adayını seçmiş ve ATT&CK metninden bir alıntıyla
açıklama üretmiştir. Bu bir çalışma demosudur; başarı yüzdesi veya bağımsız
bir değerlendirme kümesi değildir.

Diğer gerçek kontroller:

| Örnek | Gözlenen sonuç |
|---|---|
| İngilizce LSASS bellek erişimi | T1003.001 yanında T1003.004 de önerildi. Ek adayın olay metnindeki desteği yetersiz görülüyor; anlam düzeyinde uzman kontrolü gerekiyor. |
| Hesap makinesi açan kullanıcı | Eşleşme zorlanmadı, `insufficient_context` ve ek bilgi ihtiyacı döndü. |

İngilizce çıktı: [week08_rag_demo_en.json](../evidence/week08_rag_demo_en.json).
Sıradan kullanıcı davranışı: [week08_rag_demo_benign.json](../evidence/week08_rag_demo_benign.json).
Kontrol özeti: [week08_verification.json](../evidence/week08_verification.json).

Kaynak/alınan metin kontrolü, açıklamanın tüm anlamını otomatik olarak
doğrulamaz. Aynı biçimde yerel model kullanmak doğruluk garantisi vermez.
Benzerlik skorları olasılık değildir. Olayın saldırı olduğunu kesinleştirme
veya saldırgan atfı bu uygulamanın görevi değildir.

Yeni sözleşme testleri, kaynak dışı alıntı/teknik/bağlantı reddini, yerel
HTTP akışını, eksik model durumunu ve kesilen üretimi kontrol eder. Bunlar
gerçek modelin doğruluk ölçümü olarak sunulmaz. Gerçek model çalışmaları
ayrı kanıt dosyalarında tutulur.

İlk 7 haftanın 9 testiyle birlikte toplam 28 otomatik test geçti:
`python -m unittest discover -s tests -v`. Genel doğruluk, Recall@K, MRR ve
yöntem karşılaştırması 12-13. haftalarda bağımsız etiketli örneklerle yapılacaktır.

Resmî uygulama kaynakları:

- https://docs.ollama.com/api/chat
- https://docs.ollama.com/capabilities/structured-outputs

İlk 7 haftanın raporları o teslimin anlık görüntüsü olarak korunur. Güncel
durum README ve 14 haftalık takip tablosunda tutulur.
