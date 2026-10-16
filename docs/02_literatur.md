# Hafta 2 - Kısa literatür özeti

## RAG ve dil modeli

Lewis vd. (2020), dil modeliyle dış bilgi erişimini birlikte ele alır.
Bu projede ATT&CK kayıtları dış bilgi kaynağı olacaktır. İlk 7 haftada yalnız
erişim bileşeni hazırlanır; metin üretimi tamamlanmış sayılmaz. Kaynağa bağlı
üretim, yanıtın doğru olacağını tek başına garanti etmez.

Kaynak: Lewis vd., *Retrieval-Augmented Generation for Knowledge-Intensive
NLP Tasks*, NeurIPS 2020. https://arxiv.org/abs/2005.11401

## Embedding ve anlamsal arama

Reimers ve Gurevych (2019), cümleleri karşılaştırılabilir vektörlere dönüştüren
Sentence-BERT yaklaşımını açıklar. Projedeki kullanım: teknik açıklamaları ve
olay açıklamasını aynı embedding uzayında temsil edip kosinüs benzerliğiyle
sıralamak. Teknik kimliği veya tam anahtar kelime geçmese de anlamsal yakınlık
aday bulmaya yardımcı olabilir; gerçek başarı ayrıca ölçülmelidir.

Kaynak: *Sentence-BERT: Sentence Embeddings using Siamese BERT-Networks*.
EMNLP-IJCNLP 2019. DOI: 10.18653/v1/D19-1410.
https://aclanthology.org/D19-1410/

Uygulama kaynağı: https://sbert.net/examples/sentence_transformer/applications/semantic-search/README.html

## BM25 ve hibrit yaklaşım

BM25, sorgudaki terimlerin belgeyle eşleşmesine dayanan bir erişim yaklaşımıdır.
Teknik adları, araç adları ve komutların açık geçtiği sorgularda ayrı bir
karşılaştırma sunacaktır. Hibrit sistemde anahtar kelime ve vektör sonuçları
birleştirilecek; bunun daha başarılı olduğu deneyden önce varsayılmayacaktır.
BM25 uygulaması 9., hibrit uygulama 10. haftadır.

Temel bilgi erişim kaynağı: Manning, Raghavan ve Schütze (2008),
*Introduction to Information Retrieval*. https://nlp.stanford.edu/IR-book/

## Veri ve model kaynakları

- MITRE ATT&CK veri araçları: https://attack.mitre.org/resources/attack-data-and-tools/
- Resmî STIX 2.1 deposu: https://github.com/mitre-attack/attack-stix-data
- Seçilen çok dilli model kartı: https://huggingface.co/sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2

Bu not, yukarıdaki temel kaynakların projeyle ilişkisini özetler; sistematik
literatür taraması veya bütün makalelerin ayrıntılı incelemesi iddiası taşımaz.
Türkçe/İngilizce örnek demolar çalıştırıldı; genel eşleştirme başarısı bağımsız
bir etiketli veri kümesinde henüz ölçülmemiştir.
