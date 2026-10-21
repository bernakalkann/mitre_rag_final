# Hafta 3 - Gereksinimler ve teknik durum

## Kabul edilecek davranışlar

| Kod | Gereksinim | Kontrol |
|---|---|---|
| G1 | Enterprise STIX dosyasından teknik ve alt teknik ayrıştırma | Gerçek veri raporu |
| G2 | Revoked/deprecated kayıtları aramadan çıkarma | Filtre testi ve kayıt sayıları |
| G3 | Kimlik, açıklama, üst teknik, taktik, platform ve kaynak saklama | Örnek kayıt incelemesi |
| G4 | Teknik metinlerinden gerçek model embedding'i üretme | İndeks manifesti doğrulandı |
| G5 | Olay açıklamasını aynı modelle kodlayıp ilk K benzersiz tekniği getirme | Dört gerçek demo kaydedildi |
| G6 | Teknik kodu, ad, benzerlik ve resmî kaynak gösterme | Gerçek sorgu çıktılarında mevcut |
| G7 | Veri özeti ve model revizyonuyla tekrar çalıştırılabilirlik | Manifestler ve README |
| G8 | Geçersiz veri, boş/çok uzun sorgu ve bozuk indeks için açık hata | Kod kontrolleri ve temel sözleşme testleri |

## Staj kodunun incelemesi

Referans repo: https://github.com/bernakalkann/mitre-rag
İncelenen yerel HEAD: `f9f0004ec84a3dffed981a9cb75c500671789dd4`.

- `app/parsers/stix_parser.py`: çok sayıda STIX nesne türü ve ilişki çözümleme.
- `app/embeddings/ollama_embedder.py`: Ollama üzerinden embedding isteği.
- `scripts/download_attack_data.py`: kaynak, indirme tarihi ve hash manifesti.
- `app/retrieval/`, `app/llm/`, API ve arayüz: ilk 7 haftadan geniş kapsam.
- README çalışır sistem ve değerlendirmeler bildiriyor; bu incelemede o
  iddialar tekrar çalıştırılıp doğrulanmadı.

Karar: Yapıyı tümüyle kopyalamak yerine, planın ilk 7 haftasına uygun küçük ve
bağımsız bir Python paketi yazıldı. Kaynak verisi özgün manifestiyle yeniden
kullanıldı. Staj projesinin `.env`, eski değerlendirme sonuçları ve özel
belgeleri taşınmadı. Stajın kapsamı bitirme projesine zorunluluk oluşturmaz.

## İleride değerlendirilecek gereksinimler

Yerel LLM, BM25, hibrit arama ve Streamlit genel proje hedefidir; bu teslimin
çalışır bileşenleri olarak sunulmaz. Karşılaştırmada alt tekniklerin üst tekniğe
dönüşümü ve tekilleştirme politikası deney öncesinde açıkça tanımlanacaktır.
