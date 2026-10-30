# Hafta 6 - Ortam ve veri hazırlığı

## Gerçekten çalıştırılan adım

Yeni ayrıştırıcı, yereldeki resmî ATT&CK STIX kopyasıyla çalıştırıldı.
Dosyanın SHA-256 özeti önceki indirme manifestiyle eşleştirildi.
Derlemdeki koleksiyon sürümü **19.1**. Bu, kullanılan anlık görüntüdür;
bugünün en yeni ATT&CK sürümü olduğu iddia edilmez.

- İncelenen `attack-pattern`: 858.
- Revoked/deprecated nedeniyle dışlanan: 161.
- Aktif ve işlenen kayıt: 697.
- Üst teknik: 222; alt teknik: 475.
- Gerçek veri raporu: [data_report.json](../evidence/data_report.json).

Bu sayılar kullanılan dosya içindir; güncel web sayfasındaki sayılarla aynı
olması gerekmez. Önce mevcut kopyanın özgün indirme manifesti korundu.
Erişim açılınca sürümlü resmî dosya ayrıca yeniden indirildi ve SHA-256'sının
aynı olduğu doğrulandı: [download_verification.json](../evidence/download_verification.json).

## Ortam

Veri hazırlığı, 9 sözleşme testi ve gerçek embedding/arama, mevcut Python
3.12.13 ortamında çalıştırıldı. Yeni proje için temiz ortam kurulum adımları
README'dedir. Ayrı bir temiz sanal ortam kurulumu ayrıca doğrulanmadı.

İlk denemede ağ kısıtı vardı. Erişim açıldıktan sonra seçilen Sentence Transformer
modeli indirildi. Gerçek indeks oluşturuldu ve dört sorgu çalıştırıldı. Bu aşama
Ollama gerektirmez. Model ve paket sürümleri `evidence/index_manifest.json`
dosyasındadır. Model önbelleği `HF_HOME` ile proje içindeki, Git'in dışladığı
`data/model_cache` klasörüne yönlendirildi.

## Yeniden çalıştırma

```sh
python -m mitre_final download
python -m mitre_final prepare
python -m unittest discover -s tests -v
```

İndirme adımı sürüm dosyasını ve beklenen SHA-256'yı kontrol eder. Kaynak
değişirse özet körlemesine güncellenmez; fark incelenir. Ham veri Git'e eklenmez.
