# Hafta 5 - ATT&CK veri modeli

STIX `attack-pattern` nesneleri ayrıştırılır. `mitre-attack` dış referansındaki
T kodu esas alınır. Aktif Enterprise kayıtları aranır; `revoked` veya
`x_mitre_deprecated` işaretli kayıtlar dışarıda bırakılır.

| Alan | Tür | Amaç |
|---|---|---|
| stix_id | string | Özgün STIX nesne kimliği |
| attack_id | string | T1059 veya T1059.001 gibi teknik kodu |
| name | string | Teknik adı |
| description_raw | string | Özgün açıklamanın korunması |
| description | string | Arama için temizlenmiş açıklama |
| is_subtechnique | boolean | Alt teknik göstergesi |
| parent_attack_id | string/null | Alt tekniğin üst tekniği |
| tactics | string listesi | ATT&CK kill-chain aşamaları |
| platforms | string listesi | İlgili platformlar |
| source_url | string | Resmî teknik sayfası |
| modified | string/null | STIX kaydının değişiklik zamanı |

Üst teknik ilişkisi aktif `subtechnique-of` ilişkisinden alınır. İlişki yoksa
ATT&CK kimliğinin noktadan önceki bölümü kullanılır. Taktikler tek bir sınıf
etiketi olarak zorlanmaz; bir teknik birden fazla taktik içerebilir.

Temizleme: `(Citation: ...)` işaretleri kaldırılır; Markdown bağlantılarının
görünen metni korunur; HTML etiketleri ve fazla boşluklar temizlenir.
Ham açıklama, izlenebilirlik için ayrı alanda tutulur.

Gerçek veriden alınmış örnekler: [sample_records.json](../evidence/sample_records.json).
Teknik/alt teknik sayıları: [data_report.json](../evidence/data_report.json).

Kayıt nesnesinin `modified` alanı, ATT&CK sürümüyle aynı şey değildir.
Derlem sürümü ve SHA-256 özeti veri manifestinde; model revizyonu indeks
manifestinde tutulur. Boş ya da yinelenen kimlikli derlem sessizce kabul edilmez.

Kaynak: https://github.com/mitre-attack/attack-stix-data
