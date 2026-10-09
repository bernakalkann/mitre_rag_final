# Hafta 1 - ATT&CK kavramları ve proje tanımı

## Amaç

Kullanıcının yazdığı siber güvenlik olayı açıklamasından ilgili olabilecek
MITRE ATT&CK Enterprise tekniklerini kaynaklarıyla getirmek. Sonraki aşamada
yerel dil modeliyle kısa açıklama oluşturulacak ve anlamsal/hibrit erişim
aynı senaryolarda karşılaştırılacak. Uygulama karar desteği sağlar;
olayın gerçekten saldırı olduğunu otomatik doğrulamaz.

## Kavramlar

| Kavram | Anlamı | Örnek |
|---|---|---|
| Taktik | Davranışın amacı | Execution |
| Teknik | Amaca ulaşmak için kullanılan yöntem | T1059 - Command and Scripting Interpreter |
| Alt teknik | Tekniğin daha belirli bir biçimi | T1059.001 - PowerShell |
| Prosedür | Bir aktörün tekniği somut uygulama biçimi | Bir betiğin PowerShell üzerinden yürütülmesi |

Bir teknik birden fazla taktikle ilişkili olabilir. Teknik adı, saldırganın
niyetini tek başına kanıtlamaz. Örneğin PowerShell meşru yönetimde de kullanılır.

## Örnek eşleşme incelemesi

“Saldırgan Windows üzerinde PowerShell ile kötü amaçlı bir betik çalıştırdı”
girdisinde gözlenen davranış komut/betik yürütmedir. T1059.001 bu davranış
için incelenecek adaydır: https://attack.mitre.org/techniques/T1059/001/
Bu örnek elle kurulmuş açıklayıcı bir senaryodur; çalıştırılmış model çıktısı değildir.

## Araştırma sorusu

MITRE ATT&CK tekniklerini bulmada anlamsal arama ile anahtar kelime ve
anlamsal aramayı birleştiren hibrit yaklaşımın doğruluk ve yanıt süresi nasıl
farklılaşır? İleride Recall@K, MRR ve süre ölçümleri kullanılacaktır.

Kapsam: Enterprise ATT&CK, kısa doğal dil olayı, kaynaklı aday teknikler.
Gerçek zamanlı SIEM, model eğitimi, gerçek sistemlere saldırı ve üretim ortamı
kurulumu kapsam dışındadır. Kaynak: https://attack.mitre.org/
