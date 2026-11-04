# Drive teslim listesi

Hedef, öğrencinin verdiği mevcut Drive klasörüdür. Bu belge, Drive'a yükleme
yapıldığını iddia etmez. Doğrudan yükleme erişimi bulunmadığında dosyalar
öğrenci tarafından yüklenir.

## Önerilen düzen

| Klasör | Dosyalar |
|---|---|
| 01_Plan | Danışmanın onayladığı özgün 14 haftalık plan PDF'si |
| 02_Hafta_01_07 | `docs/01_...md` ile `07_...md` arasındaki yedi belge |
| 02_Hafta_01_07 | Toplu okunabilir sürüm: `docs/MITRE_RAG_Hafta_01_07_Rapor.pdf` |
| 03_Kanitlar | `evidence/data_report.json`, `sample_records.json`, `verification.json` |
| 04_Demo | Gerçek indeks sonrası `semantic_demo_en.json`, `semantic_demo_tr.json` |
| 05_Plan_Takibi | `14_haftalik_takip.md` |

Repo: https://github.com/bernakalkann/mitre_rag_final

## Güncel durum ve yüklemeden önce

Gerçek model indeksi ve dört demo tamamlandı. Arama sonuçları ve indeks
manifesti kaydedildi. Drive'a henüz yükleme yapılmadı.

- Belgeleri okuyup kendi anlatımınıza uygunluğunu kontrol edin.
- İlk 7 haftanın teknik çıktıları hazırdır; belgeleri okuyup sunum provasını yapın.
- Dört demoyu genel başarı yüzdesi olarak sunmayın.
- Model ağırlıkları, `.venv`, ham veri, `.env` ve stajın özel yönergesini teslim paketine eklemeyin.
- Plan PDF'si danışmanın verdiği orijinal dosya olarak ayrıca eklenir; bu repoda kişisel kaynak belge dağıtılmaz.

Markdown belgeler GitHub'da okunabilir. Yedi haftalık araştırma/teknik notların
birleştirilmiş PDF sürümü ayrıca `docs/` altında bulunur.
