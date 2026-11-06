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

### Erken demo arayüzü

Test ve gösterim için 11. haftadaki basit arayüzün ilk sürümü öne alınmıştır.
Mevcut anlamsal arama ve temel RAG akışı Streamlit üzerinden kullanılabilir.
Bu ek çalışma, 11. haftanın bütünüyle tamamlandığı anlamına gelmez;
BM25 ve hibrit arama henüz eklenmemiştir.

Hazır indeks ve model önbelleği bulunan ortamda repo kökünden:

```sh
python -m pip install -r requirements.txt
python -m streamlit run streamlit_app.py --server.address 127.0.0.1 --server.port 8503
```

RAG seçeneği için yerel Ollama servisinin ve `qwen3:8b` modelinin hazır olması gerekir.
İndeks hazırlama adımları [8. hafta belgesindedir](docs/08_temel_rag.md).
Ekran aday teknikleri, kaynak metinlerini, RAG açıklamasını ve JSON indirme seçeneğini gösterir.

## Sonraki görevler

| Hafta | Planlanan çalışma |
|---|---|
| 9 | BM25 arama modülü |
| 10 | Hibrit arama ve ilk karşılaştırmalar |
| 11 | Yerel LLM ve kullanıcı arayüzü |
| 12 | Doğruluğu kontrol edilmiş etiketli test senaryoları |
| 13 | Recall@K, MRR, yanıt süresi ve hata analizi |
| 14 | Son kontroller, rapor, demo ve sunum |
