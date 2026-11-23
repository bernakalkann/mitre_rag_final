# 9. ve 10. hafta · BM25 ve hibrit arama

## 9. hafta · BM25

BM25, ATT&CK Enterprise 19.1’deki 697 etkin teknik ve alt tekniği kodu, adı ve temizlenmiş açıklaması üzerinden arar. Her ATT&CK kodu tek belgedir. Sorgu ve belgeler aynı sözcük ayırma kurallarıyla işlenir. İşleme Unicode normalleştirmesi, harf duyarsızlaştırma ve sınırlı İngilizce/Türkçe işlev sözcüğü ayıklaması içerir. Teknik kodları (örneğin T1059.001) bütün tutulur.

Ters indeks ilk kullanımda hazırlanır ve süreç belleğinde SHA-256 değerine göre önbelleğe alınır. BM25, kelime sıklığı ve belge uzunluğunu k1=1.2 ve b=0.75 ile dengeler. Ortak terim bulunmazsa aday listesi boştur. Sonuçlarda kaynak bağlantısı ve açıklamadan bir alıntı gösterilir. BM25 sorgusu mevcut indeksin kayıtlarını kullanır ve embedding modeli yüklemeden çalışır.

```sh
python -m mitre_final search "T1059.001" --method bm25 --top-k 5
```

## 10. hafta · Hibrit arama

Reciprocal Rank Fusion (RRF), anlamsal aramanın kosinüs skorunu ve BM25 skorunu ortak bir ölçeğe dönüştürme gereksinimini ortadan kaldırır. Her listenin ilk 50 adayına bakılır. Bir tekniğin skoru listelerdeki 1 tabanlı sıraları için `1 / (60 + sıra)` katkılarının toplamıdır. Sonuçlar ATT&CK koduna göre birleştirilir. İki listede de bulunan adaylar iki katkı alır. Çıktıda her adayın bileşen sıraları gösterilir.

Kanıt Masası ve Streamlit üzerinden ATT&CK için üç yöntem seçilebilir. NIST CSF 2.0 araması tüm modlarda anlamsal çalışır. Kaynaklı açıklama modu 8. haftada doğrulanan anlamsal adayları kullanır. 11. haftada demoya ilişkin plan görevleri sürer.

```sh
export HF_HOME="$PWD/data/model_cache"
python -m mitre_final search "Windows scheduled task at user logon" --method hybrid --offline
python -m mitre_final compare --output evidence/week10_retrieval_comparison.json
```

## İlk karşılaştırma

Aynı dört demo sorgusu, aynı ATT&CK verisi ve önbellekteki çok dilli MiniLM modeliyle çalıştırıldı. Aşağıdaki sıra, incelenen ATT&CK kodunun ilk beşteki konumudur.

| Demo sorgusu | İncelenen kod | Anlamsal | BM25 | Hibrit |
|---|---|---:|---:|---:|
| PowerShell betiği (İngilizce) | T1059.001 | 1 | İlk 5 dışında | 5 |
| PowerShell betiği (Türkçe) | T1059.001 | 1 | 1 | 1 |
| Zamanlanmış görev (İngilizce) | T1053.005 | 2 | 1 | 1 |
| LSASS belleğine erişim (İngilizce) | T1003.001 | 1 | 1 | 1 |

Hibrit arama zamanlanmış görev örneğinde beklenen alt tekniği ilk sıraya yükseltti. İngilizce PowerShell örneğinde anlamsal arama hedef kodu ilk sırada bulurken hibrit aramada kod beşinci sıraya indi.

[Karşılaştırma çıktısı](../evidence/week10_retrieval_comparison.json) aday listelerini ve sorgu sürelerini, ATT&CK sürümünü ve SHA-256 değerlerini, model revizyonunu ve çalıştırma ortamını içerir. Süreler ısınmış indeksle yapılan tek çalıştırmada ölçüldü. 12. haftada doğrulanmış etiketli test kümesi hazırlanacak, 13. haftada Recall@K, MRR ve yanıt süresi bu kümede ölçülecek.
