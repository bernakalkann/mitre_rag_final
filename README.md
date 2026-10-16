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

Tamamlanan haftalara ait çıktılar aşağıda listelenmiştir.

| Hafta | Görev | Hazırlanan çıktı | Durum |
|---|---|---|---|
| 1 | MITRE ATT&CK yapısını inceleme | [Kavram notları ve proje tanımı](docs/01_kavramlar_ve_proje.md) | Tamamlandı |
| 2 | RAG ve bilgi erişimi temellerini inceleme | [Kısa literatür özeti](docs/02_literatur.md) | Tamamlandı |

## Sonraki görevler

| Hafta | Planlanan çalışma |
|---|---|
| 3 | Gereksinimler ve kod incelemesi |
| 4 | Teknoloji ve mimari |
| 5 | ATT&CK veri yapısı |
| 6 | Ortam ve veri hazırlığı |
| 7 | Anlamsal arama |
| 8 | Temel RAG akışı |
| 9 | BM25 |
| 10 | Hibrit arama |
| 11 | Yerel LLM ve arayüz |
| 12 | Test senaryoları |
| 13 | Deney ve analiz |
| 14 | Son kontrol ve sunum |
