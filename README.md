# MITRE-RAG

## Projenin amacı ve kapsamı

Bu bitirme projesi, kullanıcı tarafından girilen bir siber güvenlik olayı açıklamasını MITRE ATT&CK Enterprise teknikleriyle eşleştiren bir uygulama geliştirmeyi amaçlar. Sistem, ilgili teknikleri ATT&CK kodları ve kaynaklarıyla gösterecek; yerel bir dil modeli yardımıyla kısa açıklamalar oluşturacaktır.

Araştırma sorusu, anlamsal arama ile anahtar kelime ve anlamsal aramayı birleştiren hibrit yaklaşımın doğruluk ve yanıt süresi bakımından nasıl farklılaştığıdır. İki yöntem aynı etiketli örnekler üzerinde Recall@K, MRR ve yanıt süresiyle karşılaştırılacaktır.

14 haftalık çalışma planındaki temel kapsam:

- MITRE ATT&CK Enterprise STIX/JSON verisini okuma ve işleme.
- Doğal dilde güvenlik olayı açıklaması alma.
- Teknik açıklamalarından embedding üretme ve anlamsal arama yapma.
- BM25 ile anahtar kelime tabanlı arama geliştirme.
- Anlamsal arama ve BM25 sonuçlarını hibrit aramada birleştirme.
- Yerel LLM ile teknik kodu ve kaynaklara dayanan kısa açıklama sunma.
- Streamlit ile basit bir demo arayüzü hazırlama.
- Farklı teknikleri temsil eden 30–40 etiketli örnek üzerinde yöntemleri karşılaştırma.

Zaman kalırsa reranking, örnek logların daha ayrıntılı analizi, gelişmiş metadata filtreleme ve alt tekniklerin ayrıca değerlendirilmesi ele alınacaktır. Gerçek zamanlı SIEM entegrasyonu, sıfırdan model eğitimi, gerçek sistemlere saldırı uygulanması ve geniş ölçekli üretim ortamı kurulumu kapsam dışındadır.

## Tamamlanan görevler

İlk 8 haftaya ait belgeler, veri işleme, anlamsal arama ve temel RAG akışı hazırlanmıştır. Olay açıklamasından kaynaklı yanıt üretimine kadar akış gerçek ATT&CK verisi, embedding modeli ve yerel LLM ile çalıştırılmıştır.

| Hafta | Görev | Hazırlanan çıktı | Durum |
|---|---|---|---|
| 1 | MITRE ATT&CK yapısını inceleme | [Kavram notları ve proje tanımı](docs/01_kavramlar_ve_proje.md) | Tamamlandı |
| 2 | RAG ve bilgi erişimi temellerini inceleme | [Kısa literatür özeti](docs/02_literatur.md) | Tamamlandı |
| 3 | Gereksinimleri belirleme ve mevcut kodu inceleme | [Gereksinimler ve teknik durum notu](docs/03_gereksinimler_ve_inceleme.md) | Tamamlandı |
| 4 | Teknoloji seçimi ve sistem mimarisini hazırlama | [Mimari ve teknoloji listesi](docs/04_mimari.md) | Tamamlandı |
| 5 | ATT&CK veri yapısını inceleme | [Veri modeli](docs/05_veri_modeli.md) ve [örnek kayıtlar](evidence/sample_records.json) | Tamamlandı |
| 6 | Ortam ve veri hazırlığını yapma | [Çalışan veri işleme adımı](docs/06_ortam_ve_veri.md) | Tamamlandı |
| 7 | Embedding üretme ve benzerlik aramasını geliştirme | [Anlamsal arama modülü](docs/07_anlamsal_arama.md) ve [demo çıktıları](evidence/demo_summary.json) | Tamamlandı |
| 8 | Aday tekniklerden temel yanıt akışını oluşturma | [İlk uçtan uca RAG demosu](docs/08_temel_rag.md) ve [gerçek çıktı](evidence/week08_rag_demo_tr.json) | Tamamlandı |
| 9 | BM25 ile anahtar kelime araması | [BM25 arama notları](docs/09_10_bm25_ve_hibrit_arama.md) | Tamamlandı |

### Erken demo arayüzü

Test ve gösterim için 11. haftadaki basit arayüzün ilk sürümü öne alınmıştır.
Anlamsal arama ve temel RAG akışı **Kanıt masası** web arayüzü ve Streamlit
üzerinden kullanılabilir. İki arayüz aynı Python analiz servisini çağırır.

Hazır indeks ve model önbelleği bulunan ortamda repo kökünden:

```sh
python -m pip install -r requirements.txt
python -m uvicorn web.server:app --host 127.0.0.1 --port 8503
```

Kanıt Masası [8503](http://127.0.0.1:8503/) adresinde açılır. Streamlit ekranını
da kullanmak isterseniz onu ayrı bir terminalde varsayılan Streamlit portuyla başlatın:

```sh
python -m streamlit run streamlit_app.py --server.address 127.0.0.1
```

Kaynaklı açıklama için yerel Ollama ve `qwen3:8b` gerekir. Yerel model hata
verdiğinde her iki kaynağın adayları bağımsız olarak gösterilebilir.
İndeks hazırlama adımları [8. hafta belgesindedir](docs/08_temel_rag.md).
Analiz tamamlandığında ekran sonuçlara kayar. Geniş ekranda kanıt paneli
adayların yanında, dar ekranda seçilen satırın altında açılır. JSON çıktısı
iki arayüzde de aynı analiz verisini içerir. ATT&CK için aday sayısı 1–10
arasında ayarlanır. NIST için mevcut üç aday sınırı kullanılır.

Demo, aynı olay metnini [NIST CSF 2.0 Ek A](https://doi.org/10.6028/NIST.CSWP.29)
içindeki 106 alt kategoride de arar. NIST için kategori adı ve İngilizce sonuç
açıklaması, ATT&CK indeksinde belirtilen çok dilli MiniLM ile vektörlenir. NIST
indeksi ilk aramada CPU üzerinde hazırlanır ve uygulama sürecinin belleğinde
tutulur. İki kaynakta sıralama kosinüs benzerliğiyle ayrı yapılır. Yerel LLM
ATT&CK açıklaması üretir ve NIST adayları kendi kaynak metniyle
gösterilir. JSON çıktısı NIST sürümünü, yerel katalog SHA-256 değerini, model
revizyonunu ve benzerlik skorlarını içerir. 9. hafta BM25 modülü terminalde kullanılabilir.

## Sonraki görevler

| Hafta | Planlanan çalışma |
|---|---|
| 10 | Hibrit arama ve ilk karşılaştırmalar |
| 11 | Yerel LLM ve kullanıcı arayüzü |
| 12 | Doğruluğu kontrol edilmiş etiketli test senaryoları |
| 13 | Recall@K, MRR, yanıt süresi ve hata analizi |
| 14 | Son kontroller, rapor, demo ve sunum |
