# 9. hafta · BM25 anahtar kelime araması

## 9. hafta · BM25

BM25, ATT&CK Enterprise 19.1’deki 697 etkin teknik ve alt tekniği kodu, adı ve temizlenmiş açıklaması üzerinden arar. Her ATT&CK kodu tek belgedir. Sorgu ve belgeler aynı sözcük ayırma kurallarıyla işlenir. İşleme Unicode normalleştirmesi, harf duyarsızlaştırma ve sınırlı İngilizce/Türkçe işlev sözcüğü ayıklaması içerir. Teknik kodları (örneğin T1059.001) bütün tutulur.

Ters indeks ilk kullanımda hazırlanır ve süreç belleğinde SHA-256 değerine göre önbelleğe alınır. BM25, kelime sıklığı ve belge uzunluğunu k1=1.2 ve b=0.75 ile dengeler. Ortak terim bulunmazsa aday listesi boştur. Sonuçlarda kaynak bağlantısı ve açıklamadan bir alıntı gösterilir. BM25 sorgusu mevcut indeksin kayıtlarını kullanır ve embedding modeli yüklemeden çalışır.

```sh
python -m mitre_final search "T1059.001" --method bm25 --top-k 5
```
